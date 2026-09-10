//! The inspection surface: the beginning of the Studio experience.
//!
//! An auth contract is inspectable as data, so what the platform generated is
//! reviewable in the same way as any other part of an application.

use std::path::PathBuf;

use appport_auth_mesh_discovery::{
    discover, propose_authority, render_drift_json, render_proposal_json, render_proposal_text,
    render_reconciliation_json, render_reconciliation_text, AuthorityReconciler,
    ReconciliationResult,
};
use appport_auth_mesh_dsl::{parse_auth_block, AuthConfig};
use appport_auth_mesh_providers::ConnectorRegistry;
use appport_auth_mesh_surface::{render_json_with, render_text, AuthSurface};

pub mod control;
pub mod init;
pub mod serve;
pub mod studio;

pub const USAGE: &str = "\
authboundry — the application authority boundary

USAGE:
    authboundry inspect [FILE] [--json] [--mode embedded|standalone]
    authboundry init [PATH] [--dry-run] [--json] [--yes] [--standalone]
    authboundry attach [PATH] --upstream URL [--yes]
    authboundry status [PATH] [--server URL]
    authboundry studio [PATH] [--no-open] [--addr ADDRESS]
    authboundry verify [PATH] [--json]
    authboundry fingerprint [FILE]
    authboundry routes [FILE]
    authboundry providers [FILE]
    authboundry password-policy [FILE] [--json]
    authboundry password-policy --server URL [--json]
    authboundry password-policy propose [options] [--server URL] [--dry-run]
    authboundry serve [FILE] [options]
    authboundry connect [--server URL] [--output-token]
    authboundry propose [FILE] [--json]
    authboundry reconcile [FILE] [--json] [--check]
    authboundry drift [FILE] [--json] [--check]
    authboundry propose <change-type> [options] [--server URL] [--dry-run]
    authboundry approve [--proposal-id ID|--all] [--server URL] --yes
    authboundry apply [--proposal-id ID|--all] [--server URL] --yes
    authboundry reject [--proposal-id ID] [--reason TEXT] [--server URL]
    authboundry agents [--tenant TENANT] [--server URL]
    authboundry agent create --tenant TENANT --name NAME [--id ID] [--server URL]
    authboundry agent show ID --tenant TENANT [--server URL]
    authboundry runs --tenant TENANT --agent AGENT [--server URL]
    authboundry run show ID --tenant TENANT [--server URL]
    authboundry audit [--server URL]
    authboundry audit events --tenant TENANT [--server URL]
    authboundry audit export --tenant TENANT [--since TIMESTAMP] [--server URL]
    authboundry storage [--server URL]
    authboundry reporting [--server URL]
    authboundry policies [--server URL]
    authboundry policy show ID [--server URL]
    authboundry explain [DECISION_ID] [--server URL]

SERVE OPTIONS:
    --addr ADDRESS              listen address (default 127.0.0.1:8787)
    --tenant NAME               a tenant to serve (repeatable)
    --account USER:PASS:CLAIMS  seed a principal, e.g. alice:secret:role=owner@acme
    --grant CAPABILITY=CLAIM:V  grant a capability, e.g. invoice.read=role:owner
    --upstream ADDRESS          the application AuthBoundry sits in front of
    --public PATH               forward this path prefix without a session
    --require PATH=CAPABILITY   require a capability for this path prefix

FILE defaults to authboundry.toml, appport.auth, appport.toml or auth.appport in
the current directory. Legacy declaration names remain readable when explicit.
";

/// Candidate declaration files, in the order they are tried.
pub const DEFAULT_FILES: &[&str] = &[
    "authboundry.toml",
    "authport.toml",
    "appport.auth",
    "appport.toml",
    "auth.appport",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub message: String,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CliError {}

pub(crate) fn error(message: impl Into<String>) -> CliError {
    CliError {
        message: message.into(),
    }
}

pub fn run<I>(args: I) -> Result<Output, CliError>
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = args.into_iter().collect();
    if args.first().map(String::as_str) == Some("password-policy")
        && (args.get(1).map(String::as_str) == Some("propose")
            || args.iter().any(|arg| arg == "--server"))
    {
        return control::run(&args);
    }
    if matches!(
        args.first().map(String::as_str),
        Some(
            "connect"
                | "approve"
                | "apply"
                | "reject"
                | "agents"
                | "agent"
                | "runs"
                | "run"
                | "audit"
                | "storage"
                | "reporting"
                | "policies"
                | "policy"
                | "explain",
        )
    ) || is_control_propose(&args)
    {
        return control::run(&args);
    }
    if matches!(args.first().map(String::as_str), Some("init")) {
        return init::run(&args[1..]);
    }
    if matches!(args.first().map(String::as_str), Some("attach")) {
        return init::attach(&args[1..]);
    }
    if matches!(args.first().map(String::as_str), Some("status")) {
        return init::status(&args[1..]);
    }
    if matches!(args.first().map(String::as_str), Some("studio")) {
        return studio::run(&args[1..]);
    }
    if matches!(args.first().map(String::as_str), Some("verify")) {
        return init::verify(&args[1..]);
    }
    let mut command = None;
    let mut file: Option<PathBuf> = None;
    let mut json = false;
    let mut check = false;
    let mut mode: Option<String> = None;
    let mut serve_options = serve::ServeOptions::default();
    let mut default_tenant = "default".to_string();

    let mut index = 0usize;
    while index < args.len() {
        let arg = args[index].clone();
        index += 1;

        let value = |name: &str, index: &mut usize| -> Result<String, CliError> {
            let value = args
                .get(*index)
                .cloned()
                .ok_or_else(|| error(format!("{} needs a value", name)))?;
            *index += 1;
            Ok(value)
        };

        match arg.as_str() {
            "--json" => json = true,
            "--check" => check = true,
            "-h" | "--help" | "help" => {
                return Ok(Output {
                    text: USAGE.to_string(),
                })
            }
            "--mode" => {
                let selected = value("--mode", &mut index)?;
                if !matches!(selected.as_str(), "embedded" | "standalone") {
                    return Err(error("--mode must be embedded or standalone"));
                }
                mode = Some(selected);
            }
            "--addr" => serve_options.address = value("--addr", &mut index)?,
            "--tenant" => {
                let tenant = value("--tenant", &mut index)?;
                if serve_options.tenants.is_empty() {
                    default_tenant = tenant.clone();
                }
                serve_options.tenants.push(tenant);
            }
            "--account" => {
                let raw = value("--account", &mut index)?;
                serve_options
                    .accounts
                    .push(serve::Account::parse(&raw, &default_tenant)?);
            }
            "--grant" => {
                let raw = value("--grant", &mut index)?;
                serve_options.grants.push(serve::Grant::parse(&raw)?);
            }
            "--upstream" => serve_options.upstream = Some(value("--upstream", &mut index)?),
            "--public" => {
                let path = value("--public", &mut index)?;
                serve_options.public_paths.push(path);
            }
            "--require" => {
                let raw = value("--require", &mut index)?;
                let (path, capability) = raw
                    .split_once('=')
                    .ok_or_else(|| error("--require expects PATH=CAPABILITY"))?;
                serve_options
                    .required
                    .push((path.to_string(), capability.to_string()));
            }
            flag if flag.starts_with('-') => return Err(error(format!("unknown flag `{}`", flag))),
            value if command.is_none() => command = Some(value.to_string()),
            value if file.is_none() => file = Some(PathBuf::from(value)),
            value => return Err(error(format!("unexpected argument `{}`", value))),
        }
    }

    // Accounts may name a tenant the flags introduced later.
    for account in &serve_options.accounts {
        if !serve_options
            .tenants
            .iter()
            .any(|tenant| tenant == &account.tenant)
        {
            serve_options.tenants.push(account.tenant.clone());
        }
    }

    let command = command.unwrap_or_else(|| "inspect".to_string());
    let path = resolve_file(file.clone());
    let (path, source) = match path {
        Ok(path) => {
            let source = std::fs::read_to_string(&path)
                .map_err(|err| error(format!("cannot read `{}`: {}", path.display(), err)))?;
            (Some(path), source)
        }
        Err(err)
            if matches!(
                command.as_str(),
                "inspect" | "propose" | "reconcile" | "drift"
            ) && file.is_none() =>
        {
            let root = std::env::current_dir()
                .map_err(|err| error(format!("cannot read cwd: {}", err)))?;
            if discover(&root).is_none() {
                return Err(err);
            }
            (None, "use auth { providers = [local] }\n".to_string())
        }
        Err(err) => return Err(err),
    };
    let config = parse_auth_block(&source).map_err(|err| {
        let display = path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "(default contract)".to_string());
        error(format!("{}: {}", display, err.message))
    })?;

    if command == "serve" && serve_options.upstream.is_none() {
        let root = path
            .as_ref()
            .and_then(|path| path.parent())
            .unwrap_or_else(|| std::path::Path::new("."));
        serve_options.upstream = init::adoption_upstream(root);
    }

    let text = match command.as_str() {
        "inspect" => {
            let root = path
                .as_ref()
                .and_then(|path| path.parent())
                .map(|path| path.to_path_buf())
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            describe(&config, json, mode.as_deref(), Some(&root))
        }
        "propose" => {
            let root = path
                .as_ref()
                .and_then(|path| path.parent())
                .map(|path| path.to_path_buf())
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let app = discover(&root)
                .ok_or_else(|| error("no supported application found to propose authority"))?;
            let proposal = propose_authority(
                &app,
                config.fingerprint(),
                0,
                &std::collections::BTreeMap::new(),
            );
            if json {
                render_proposal_json(&proposal)
            } else {
                render_proposal_text(&proposal)
            }
        }
        "reconcile" => {
            let result = local_reconciliation(&config, path.as_deref())?;
            if check && !result.drift.is_empty() {
                return Err(error(format!(
                    "authority drift detected ({} unresolved items)",
                    result.drift.len()
                )));
            }
            if json {
                render_reconciliation_json(&result)
            } else {
                render_reconciliation_text(&result)
            }
        }
        "drift" => {
            let result = local_reconciliation(&config, path.as_deref())?;
            if check && !result.drift.is_empty() {
                return Err(error(format!(
                    "authority drift detected ({} unresolved items)",
                    result.drift.len()
                )));
            }
            if json {
                render_drift_json(&result)
            } else {
                render_drift_text(&result)
            }
        }
        "fingerprint" => format!(
            "contract {}\nsurface  {}\n",
            config.fingerprint(),
            AuthSurface::derive(&config).fingerprint()
        ),
        "routes" => {
            let mut out = String::from("METHOD             PATH                  AUTHORITY\n");
            for route in &AuthSurface::derive(&config).routes {
                let methods = route
                    .methods
                    .iter()
                    .map(|method| method.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                out.push_str(&format!("{:<18} {:<21} AuthBoundry\n", methods, route.path));
            }
            let root = path
                .as_ref()
                .and_then(|path| path.parent())
                .unwrap_or_else(|| std::path::Path::new("."));
            if let Some(routes) = init::discovered_routes(root) {
                for route in routes {
                    out.push_str(&format!(
                        "{:<18} {:<21} unprotected\n",
                        route.method, route.path
                    ));
                }
            }
            out
        }
        "providers" => describe_providers(&config)?,
        "password-policy" => {
            if args.iter().any(|arg| arg == "--server") {
                return control::run(&args);
            }
            if args.get(1).map(String::as_str) == Some("propose") {
                return control::run(&args);
            }
            describe_password_policy(&config, json)
        }
        "serve" => return run_server(config, &serve_options),
        other => return Err(error(format!("unknown command `{}`\n\n{}", other, USAGE))),
    };

    Ok(Output { text })
}

fn describe_password_policy(config: &AuthConfig, json: bool) -> String {
    let policy = &config.password_policy;
    if json {
        return format!(
            "{{\"min_length\": {}, \"max_length\": {}, \"require_uppercase\": {}, \"require_lowercase\": {}, \"require_number\": {}, \"require_special_character\": {}, \"expiration_days\": {}, \"history_count\": {}, \"allow_password_change\": {}, \"allow_password_reset\": {}, \"contract_fingerprint\": \"{}\", \"policy_revision\": \"{}\"}}\n",
            policy.min_length,
            policy.max_length,
            policy.require_uppercase,
            policy.require_lowercase,
            policy.require_number,
            policy.require_special_character,
            policy
                .password_expiration_days
                .map(|days| days.to_string())
                .unwrap_or_else(|| "null".to_string()),
            policy.password_history_count,
            policy.allow_password_change,
            policy.allow_password_reset,
            config.fingerprint(),
            policy.revision_fingerprint()
        );
    }
    format!(
        "Password Policy\n  Minimum length       {}\n  Maximum length       {}\n  Uppercase            {}\n  Lowercase            {}\n  Number               {}\n  Special character    {}\n  Password expiration  {}\n  Password history     {} passwords\n",
        policy.min_length,
        policy.max_length,
        required(policy.require_uppercase),
        required(policy.require_lowercase),
        required(policy.require_number),
        required(policy.require_special_character),
        policy
            .password_expiration_days
            .map(|days| format!("{} days", days))
            .unwrap_or_else(|| "Disabled".to_string()),
        policy.password_history_count
    )
}

fn required(value: bool) -> &'static str {
    if value {
        "Required"
    } else {
        "Not required"
    }
}

fn local_reconciliation(
    config: &AuthConfig,
    path: Option<&std::path::Path>,
) -> Result<ReconciliationResult, CliError> {
    let root = path
        .and_then(|path| path.parent())
        .map(|path| path.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let app =
        discover(&root).ok_or_else(|| error("no supported application found to reconcile"))?;
    Ok(AuthorityReconciler::reconcile(
        None,
        &app,
        config.fingerprint(),
        0,
        &std::collections::BTreeMap::new(),
        &[],
    ))
}

fn render_drift_text(result: &ReconciliationResult) -> String {
    let mut out = String::from("AuthBoundry Authority Drift\n");
    if result.drift.is_empty() {
        out.push_str("No authority drift detected.\n");
        return out;
    }
    for item in &result.drift {
        out.push_str(&format!(
            "{}\n  {}\n  previous: {}\n  current: {}\n  authority: {}\n  action: {}\n",
            item.kind.as_str().to_ascii_uppercase(),
            item.route,
            item.previous_state,
            item.current_state,
            item.authority_state,
            item.recommended_action
        ));
    }
    out.push_str("No authority was changed.\n");
    out
}

/// Start the standalone runtime and block until the process is stopped.
fn run_server(config: AuthConfig, options: &serve::ServeOptions) -> Result<Output, CliError> {
    let running = serve::start(config, options)?;
    let address = running.authport.address();

    println!("AuthBoundry listening on http://{}", address);
    match &running.upstream {
        Some(upstream) => {
            println!("Mode:\n  standalone application boundary");
            println!("Application:\n  ATTACHED {}", upstream);
            println!("Protection:\n  ACTIVE");
        }
        None => {
            println!("Mode:\n  standalone authority surface");
            println!("Application:\n  NOT ATTACHED");
            println!("AuthBoundry is serving authentication and authority endpoints only.");
            println!("It is NOT currently protecting or proxying an application.");
        }
    }
    println!("  sign in    http://{}/auth/login", address);
    println!("  session    http://{}/auth/session", address);
    println!("  providers  http://{}/auth/providers", address);

    running.authport.wait();
    Ok(Output {
        text: String::new(),
    })
}

fn is_control_propose(args: &[String]) -> bool {
    if args.first().map(String::as_str) != Some("propose") {
        return false;
    }
    matches!(
        args.get(1).map(String::as_str),
        Some(
            "protect-route"
                | "unprotect-route"
                | "set-policy"
                | "enable-provider"
                | "disable-provider"
        )
    ) || args
        .iter()
        .any(|arg| arg == "--server" || arg == "--dry-run")
}

fn describe(
    config: &AuthConfig,
    json: bool,
    mode: Option<&str>,
    root: Option<&std::path::Path>,
) -> String {
    let surface = AuthSurface::derive(config);
    let application = root.and_then(discover);
    if !json {
        let mut out = render_text(&surface);
        if let Some(app) = application {
            let adoption = root.and_then(init::read_adoption);
            let upstream = adoption
                .as_ref()
                .and_then(|state| state.upstream.as_deref());
            let integration_mode = adoption
                .as_ref()
                .map(|state| state.mode.as_str())
                .unwrap_or("standalone");
            let proposal = propose_authority(
                &app,
                config.fingerprint(),
                0,
                &std::collections::BTreeMap::new(),
            );
            out.push('\n');
            out.push_str("Application discovery:\n");
            out.push_str(&format!(
                "  found: {}\n",
                app.name.as_deref().unwrap_or("(unknown)")
            ));
            out.push_str("Application integration:\n");
            out.push_str(&format!(
                "  status: {}\n  mode: {}\n  upstream: {}\n",
                if upstream.is_some() {
                    "configured"
                } else {
                    "unattached"
                },
                integration_mode,
                upstream.unwrap_or("none")
            ));
            out.push_str(&format!(
                "Routes:\n  {} discovered\n",
                proposal.routes.len()
            ));
            for route in &proposal.routes {
                out.push_str(&format!("  {:<6} {}\n", route.method, route.path));
            }
            out.push_str("Inferred capabilities:\n");
            if proposal
                .routes
                .iter()
                .all(|route| route.inference.is_none())
            {
                out.push_str("  none\n");
            }
            for route in proposal
                .routes
                .iter()
                .filter(|route| route.inference.is_some())
            {
                let inference = route.inference.as_ref().unwrap();
                out.push_str(&format!(
                    "  {} ({})\n",
                    inference.capability,
                    inference.confidence.as_str()
                ));
            }
            out.push_str("Safe defaults:\n");
            if proposal.routes.is_empty() {
                out.push_str("  protected routes deny by default\n");
            }
            for route in &proposal.routes {
                out.push_str(&format!(
                    "  {:<6} {:<24} {}\n",
                    route.method,
                    route.path,
                    route.protection.as_str()
                ));
            }
            out.push_str("Authority:\n  configured\nProtection:\n  inactive\n");
            out.push_str("Nothing has been changed.\n");
        }
        return out;
    }

    // The contract is the same in both placements; the mode only says which
    // one this invocation is describing.
    let extra = match mode {
        Some(mode) => vec![("mode".to_string(), mode.to_string())],
        None => vec![("mode".to_string(), "any".to_string())],
    };
    render_json_with(&surface, &extra)
}

/// Provider status comes from the connector registry the runtime would build,
/// so inspection cannot disagree with what actually happens at login.
fn describe_providers(config: &AuthConfig) -> Result<String, CliError> {
    let registry = ConnectorRegistry::from_config(config)
        .map_err(|err| error(format!("connector registry: {}", err)))?;

    Ok(registry
        .metadata()
        .iter()
        .map(|metadata| {
            format!(
                "{:<12} {:<16} {}\n",
                metadata.id,
                metadata.kind.as_str(),
                metadata.status.as_str()
            )
        })
        .collect())
}

fn resolve_file(file: Option<PathBuf>) -> Result<PathBuf, CliError> {
    if let Some(file) = file {
        return Ok(file);
    }
    for candidate in DEFAULT_FILES {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Ok(path);
        }
    }
    Err(error(format!(
        "no auth declaration found (looked for {})",
        DEFAULT_FILES.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_no_deprecated_public_name(surface: &str) {
        for forbidden in ["authport", "AuthPort", "_authport", "authport_"] {
            assert!(
                !surface.contains(forbidden),
                "deprecated public identifier `{}` leaked in:\n{}",
                forbidden,
                surface
            );
        }
    }

    fn write_declaration(dir: &std::path::Path, body: &str) -> PathBuf {
        let path = dir.join("appport.auth");
        std::fs::write(&path, body).unwrap();
        path
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("authport-cli-{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const DECLARATION: &str = r#"
use auth {
  providers = [local, google, github, email]
  tenant = true
  claims = {
    role = enum["owner", "admin", "member"]
    plan = enum["free", "pro"]
    billing = enum["none", "manager"]
  }
  agents = true
}
"#;

    fn run_with(args: &[&str]) -> Result<Output, CliError> {
        run(args.iter().map(|arg| arg.to_string()))
    }

    #[test]
    fn inspects_a_declaration_without_running_the_application() {
        let dir = temp_dir("inspect");
        let path = write_declaration(&dir, DECLARATION);

        let output = run_with(&["inspect", path.to_str().unwrap()]).unwrap();

        assert!(output.text.contains("Multi-tenant: yes"));
        assert!(output.text.contains("Isolation: strict"));
        assert!(output.text.contains("  ✓ local"));
        assert!(output.text.contains("  ○ google"));
        assert!(output.text.contains("  role: admin | member | owner"));
        assert!(output.text.contains("Agents:\n  enabled"));
        assert!(output.text.contains("Delegation:\n  enabled"));
        assert!(output.text.contains("/auth/delegations"));
        assert_no_deprecated_public_name(&output.text);
    }

    #[test]
    fn renders_json_routes_providers_and_fingerprints() {
        let dir = temp_dir("formats");
        let path = write_declaration(&dir, DECLARATION);
        let file = path.to_str().unwrap();

        let json = run_with(&["inspect", file, "--json"]).unwrap().text;
        assert!(json.contains("\"surface_fingerprint\""));
        assert!(json.contains("\"path\": \"/auth/login\""));
        assert!(json.contains("\"agents\": true"));
        // Inspection identifies the runtime boundary as well as the contract.
        assert!(json.contains("\"mode\": \"any\""));
        assert!(json.contains("\"boundary\": {\"contract\": \"authboundry.boundary/v1\""));
        assert!(json.contains("\"modes\": [\"embedded\", \"standalone\"]"));
        assert!(json.contains("\"session_credential\": \"cookie:authboundry_session\""));
        assert!(json.contains("\"aliases\": [\"/auth/sign-in\"]"));

        let standalone = run_with(&["inspect", file, "--json", "--mode", "standalone"])
            .unwrap()
            .text;
        assert!(standalone.contains("\"mode\": \"standalone\""));
        // The contract itself does not change with the placement.
        assert_eq!(
            standalone.replace("\"standalone\",", "\"any\","),
            json,
            "only the mode line may differ between placements"
        );

        let routes = run_with(&["routes", file]).unwrap().text;
        assert!(routes.contains("GET,POST           /auth/login"));
        assert!(routes.contains("POST               /auth/authorize"));

        let providers = run_with(&["providers", file]).unwrap().text;
        assert!(providers.contains("local        local            supported"));
        assert!(providers.contains("google       oauth            declared"));

        let fingerprint = run_with(&["fingerprint", file]).unwrap().text;
        assert!(fingerprint.starts_with("contract "));
        // Inspection is a pure function of the declaration.
        assert_eq!(fingerprint, run_with(&["fingerprint", file]).unwrap().text);
    }

    #[test]
    fn reports_problems_instead_of_guessing() {
        let dir = temp_dir("errors");
        let path = write_declaration(&dir, "use auth { providers = [pigeon] }");
        let file = path.to_str().unwrap();

        assert!(run_with(&["providers", file])
            .unwrap_err()
            .message
            .contains("unknown connector `pigeon`"));
        assert!(run_with(&["inspect", "does-not-exist.auth"])
            .unwrap_err()
            .message
            .contains("cannot read"));
        assert!(run_with(&["explode", file])
            .unwrap_err()
            .message
            .contains("unknown command"));
        assert!(run_with(&["--nope"])
            .unwrap_err()
            .message
            .contains("unknown flag"));
        assert!(run_with(&["--help"]).unwrap().text.contains("USAGE"));
        assert!(run_with(&["inspect", file, "--mode", "sideways"])
            .unwrap_err()
            .message
            .contains("--mode must be"));
    }

    #[test]
    fn parses_serve_deployment_flags() {
        let account = serve::Account::parse("alice:secret:role=owner,plan=pro@acme", "default")
            .expect("account parses");
        assert_eq!(account.tenant, "acme");
        assert_eq!(account.username, "alice");
        assert_eq!(
            account.claims.get("role").map(String::as_str),
            Some("owner")
        );

        let default_tenant = serve::Account::parse("bob:secret", "globex").expect("account parses");
        assert_eq!(default_tenant.tenant, "globex");
        assert!(default_tenant.claims.is_empty());
        assert!(serve::Account::parse("nopassword", "default").is_err());

        let grant = serve::Grant::parse("invoice.read=role:owner").expect("grant parses");
        assert_eq!(grant.capability, "invoice.read");
        assert_eq!(grant.claim, "role");
        assert_eq!(grant.value, "owner");
        assert!(serve::Grant::parse("invoice.read").is_err());
    }

    #[test]
    fn serve_runs_a_real_authority_service() {
        use appport_auth_mesh_server::{cookie_value, send, ClientRequest};

        let dir = temp_dir("serve");
        let path = write_declaration(&dir, DECLARATION);
        let config = parse_auth_block(&std::fs::read_to_string(&path).unwrap()).unwrap();

        let options = serve::ServeOptions {
            address: "127.0.0.1:0".to_string(),
            tenants: vec!["acme".to_string()],
            accounts: vec![serve::Account::parse(
                "alice:alice-secret:role=owner,plan=pro,billing=none",
                "acme",
            )
            .unwrap()],
            grants: vec![serve::Grant::parse("invoice.read=role:owner").unwrap()],
            ..serve::ServeOptions::default()
        };

        let running = serve::start(config, &options).expect("AuthBoundry binds");
        let address = running.authport.address();

        // The generated sign-in UI is served from the same contract.
        let ui = send(address, &ClientRequest::get("/auth/login")).expect("ui responds");
        assert_eq!(ui.status, 200);
        assert!(ui.body_string().contains("Local Directory"));

        // Providers come from the one declaration.
        let providers = send(address, &ClientRequest::get("/auth/providers")).unwrap();
        assert!(providers.body_string().contains("\"id\": \"local\""));

        // No session, no authority.
        let anonymous = send(address, &ClientRequest::get("/auth/session")).unwrap();
        assert_eq!(anonymous.status, 401);

        let signed_in = send(
            address,
            &ClientRequest::post_json(
                "/auth/sign-in",
                "{\"tenant\": \"acme\", \"connector\": \"local\", \"username\": \"alice\", \"password\": \"alice-secret\"}",
            ),
        )
        .expect("sign-in responds");
        assert_eq!(signed_in.status, 200);
        let credential =
            cookie_value(&signed_in, "authboundry_session").expect("a session cookie is issued");

        let granted = send(
            address,
            &ClientRequest::post_json("/auth/authorize", "{\"capability\": \"invoice.read\"}")
                .with_cookie("authboundry_session", &credential),
        )
        .unwrap();
        assert!(granted.body_string().contains("\"allowed\": true"));

        let refused = send(
            address,
            &ClientRequest::post_json("/auth/authorize", "{\"capability\": \"billing.charge\"}")
                .with_cookie("authboundry_session", &credential),
        )
        .unwrap();
        assert!(refused.body_string().contains("\"allowed\": false"));

        running.authport.shutdown();
    }

    fn write_express_app(dir: &std::path::Path) {
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"zero-app","scripts":{"start":"node src/server.js"},"dependencies":{"express":"latest"}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/server.js"),
            "const express = require('express');\nconst app = express();\napp.get('/', handler);\napp.get('/health', handler);\napp.post('/invoices', handler);\n",
        )
        .unwrap();
    }

    fn write_pr18_express_app(dir: &std::path::Path) {
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"pr18-app","scripts":{"dev":"node src/server.js"},"dependencies":{"express":"latest"}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/server.js"),
            "const express = require('express');\nconst app = express();\napp.get('/health', health);\napp.get('/invoices', listInvoices);\napp.get('/invoices/:id', getInvoice);\napp.post('/invoices', createInvoice);\napp.post('/refunds', createRefund);\n",
        )
        .unwrap();
    }

    #[test]
    fn inspect_and_propose_discovered_routes_without_changing_authority() {
        let dir = temp_dir("propose-express");
        write_express_app(&dir);
        std::fs::write(
            dir.join("src/server.js"),
            "const express = require('express');\nconst app = express();\napp.get('/health', handler);\napp.get('/invoices', handler);\napp.post('/invoices', handler);\napp.get('/customers', handler);\napp.post('/billing/charge', handler);\n",
        )
        .unwrap();
        let path = write_declaration(&dir, "use auth { providers = [local] }");

        let inspect = run_with(&["inspect", path.to_str().unwrap()]).unwrap().text;
        assert!(inspect.contains("Application discovery:"));
        assert!(inspect.contains("GET    /health"));
        assert!(inspect.contains("invoice.read (high)"));
        assert!(inspect.contains("billing.charge (high)"));
        assert!(inspect.contains("Nothing has been changed."));

        let proposal = run_with(&["propose", path.to_str().unwrap()]).unwrap().text;
        assert!(proposal.contains("AUTHORITY PROPOSAL"));
        assert!(proposal.contains("POST /invoices\n  → invoice.create"));
        assert!(proposal.contains("POST /billing/charge\n  → billing.charge"));
        assert!(proposal.contains("RECOMMENDED PROTECTION"));
        assert!(proposal.contains("Nothing has been changed."));

        let json = run_with(&["propose", path.to_str().unwrap(), "--json"])
            .unwrap()
            .text;
        assert!(json.contains("\"application\": \"zero-app\""));
        assert!(json.contains("\"contract_fingerprint\""));
        assert!(json.contains("\"live_revision\": 0"));
        assert!(json.contains("\"action\": \"protect_route\""));
    }

    #[test]
    fn reconcile_and_drift_report_machine_readable_review_items() {
        let dir = temp_dir("reconcile-express");
        write_express_app(&dir);
        std::fs::write(
            dir.join("src/server.js"),
            "const express = require('express');\nconst app = express();\napp.post('/refunds', handler);\n",
        )
        .unwrap();
        let path = write_declaration(&dir, "use auth { providers = [local] }");

        let reconcile = run_with(&["reconcile", path.to_str().unwrap()])
            .unwrap()
            .text;
        assert!(reconcile.contains("AuthBoundry Authority Reconciliation"));
        assert!(reconcile.contains("POST /refunds"));
        assert!(reconcile.contains("refund.create"));
        assert!(reconcile.contains("No authority was changed."));

        let json = run_with(&["reconcile", path.to_str().unwrap(), "--json"])
            .unwrap()
            .text;
        assert!(json.contains("\"new_routes\": 1"));
        assert!(json.contains("\"unsafe_automatic_changes\": 0"));
        assert!(json.contains("\"capability\": \"refund.create\""));

        let drift = run_with(&["drift", path.to_str().unwrap(), "--json"])
            .unwrap()
            .text;
        assert!(drift.contains("\"type\": \"new_route\""));
        assert!(run_with(&["reconcile", path.to_str().unwrap(), "--check"])
            .unwrap_err()
            .message
            .contains("authority drift detected"));
    }

    #[test]
    fn init_previews_applies_and_is_idempotent_for_existing_express_app() {
        let dir = temp_dir("init-express");
        write_express_app(&dir);
        std::fs::write(
            dir.join(".env"),
            "GOOGLE_CLIENT_ID=value\nGOOGLE_CLIENT_SECRET=hidden\n",
        )
        .unwrap();

        let preview = run_with(&["init", dir.to_str().unwrap(), "--dry-run"])
            .unwrap()
            .text;
        assert!(preview.contains("AuthBoundry found your application."));
        assert!(preview.contains("Framework:\n  Express"));
        assert!(preview.contains("Google OAuth configuration"));
        assert!(!preview.contains("hidden"));
        assert!(preview.contains("Files to modify:"));
        assert!(preview.contains("src/server.js"));
        assert_no_deprecated_public_name(&preview);
        assert!(!dir.join("authboundry.toml").exists());

        let json = run_with(&["init", dir.to_str().unwrap(), "--json"])
            .unwrap()
            .text;
        assert!(json.contains("\"application\": \"zero-app\""));
        assert!(json.contains("\"framework\": \"Express\""));
        assert!(json.contains("\"already_configured\": false"));
        assert!(json.contains("\"changes\": ["));

        let applied = run_with(&["init", dir.to_str().unwrap(), "--yes"])
            .unwrap()
            .text;
        assert!(applied.contains("AuthBoundry adoption complete."));
        assert!(applied.contains("✓ 3 application routes discovered"));
        let server = std::fs::read_to_string(dir.join("src/server.js")).unwrap();
        assert_eq!(server.matches("app.use(authboundry());").count(), 0);
        assert!(server.contains("app.get('/health'"));
        let package_json = std::fs::read_to_string(dir.join("package.json")).unwrap();
        assert!(!package_json.contains("@authboundry/core"));
        assert!(dir.join("authboundry.toml").exists());
        assert!(dir.join(".authboundry/adoption.json").exists());
        assert_no_deprecated_public_name(
            &std::fs::read_to_string(dir.join("authboundry.toml")).unwrap(),
        );
        assert_no_deprecated_public_name(
            &std::fs::read_to_string(dir.join(".authboundry/adoption.json")).unwrap(),
        );
        let adoption = std::fs::read_to_string(dir.join(".authboundry/adoption.json")).unwrap();
        assert!(adoption.contains("\"authority\": \"configured\""));
        assert!(adoption.contains("\"attachment\": \"none\""));
        assert!(adoption.contains("\"protection\": \"inactive\""));
        assert!(applied.contains("Application integration not established"));

        let second = run_with(&["init", dir.to_str().unwrap(), "--yes"])
            .unwrap()
            .text;
        assert!(second.contains("AuthBoundry already detected."));
        let server_again = std::fs::read_to_string(dir.join("src/server.js")).unwrap();
        assert_eq!(server_again.matches("app.use(authboundry());").count(), 0);

        let routes = run_with(&["routes", dir.join("authboundry.toml").to_str().unwrap()])
            .unwrap()
            .text;
        assert!(routes.contains("GET                /health"));
        assert!(routes.contains("POST               /invoices"));
        assert!(routes.contains("unprotected"));

        let verify = run_with(&["verify", dir.to_str().unwrap(), "--json"])
            .unwrap()
            .text;
        assert!(verify.contains("\"ok\": true"));
        assert!(verify.contains("\"contract_fingerprint_stable\": true"));
        assert!(verify.contains("\"authority_state_available\": true"));
    }

    #[test]
    fn pr18_golden_path_discovers_initializes_and_reviews_authority() {
        let dir = temp_dir("pr18-golden");
        write_pr18_express_app(&dir);

        let preview = run_with(&["init", dir.to_str().unwrap(), "--dry-run"])
            .unwrap()
            .text;
        assert!(preview.contains("Application:\n  pr18-app"));
        assert!(preview.contains("Package manager:\n  npm"));
        assert!(preview.contains("Run command:\n  node src/server.js"));
        assert!(preview.contains("GET    /health"));
        assert!(preview.contains("GET    /invoices/:param"));
        assert!(preview.contains("POST   /refunds"));
        assert!(preview.contains("public"));
        assert!(preview.contains("unprotected"));

        let applied = run_with(&["init", dir.to_str().unwrap(), "--yes"])
            .unwrap()
            .text;
        assert!(applied.contains("✓ 5 application routes discovered"));

        let package_json = std::fs::read_to_string(dir.join("package.json")).unwrap();
        assert!(!package_json.contains("@authboundry/core"));
        let server = std::fs::read_to_string(dir.join("src/server.js")).unwrap();
        assert!(!server.contains("@authboundry/core"));
        assert_eq!(server.matches("app.use(authboundry());").count(), 0);
        assert!(server.contains("app.post('/refunds', createRefund);"));

        let verify = run_with(&["verify", dir.to_str().unwrap()]).unwrap().text;
        assert!(verify.contains("✓ application discovered"));
        assert!(verify.contains("✓ AuthBoundry configuration present"));
        assert!(verify.contains("✓ authority state available"));

        let routes = run_with(&["routes", dir.join("authboundry.toml").to_str().unwrap()])
            .unwrap()
            .text;
        assert!(routes.contains("GET                /health"));
        assert!(routes.contains("GET                /invoices/:id"));
        assert!(routes.contains("POST               /refunds"));
        assert!(routes.contains("unprotected"));

        let proposal = run_with(&["propose", dir.join("authboundry.toml").to_str().unwrap()])
            .unwrap()
            .text;
        assert!(proposal.contains("POST /invoices\n  → invoice.create"));
        assert!(proposal.contains("POST /refunds\n  → refund.create"));
        assert!(proposal.contains("RECOMMENDED PROTECTION"));

        let standalone = temp_dir("pr18-standalone");
        write_pr18_express_app(&standalone);
        run_with(&[
            "init",
            standalone.to_str().unwrap(),
            "--standalone",
            "--yes",
        ])
        .unwrap();
        let standalone_server = std::fs::read_to_string(standalone.join("src/server.js")).unwrap();
        assert!(!standalone_server.contains("authboundry()"));
        let manifest =
            std::fs::read_to_string(standalone.join(".authboundry/adoption.json")).unwrap();
        assert!(manifest.contains("\"mode\": \"standalone\""));
        assert!(manifest.contains("\"run_command\": \"node src/server.js\""));
        let standalone_routes = run_with(&[
            "routes",
            standalone.join("authboundry.toml").to_str().unwrap(),
        ])
        .unwrap()
        .text;
        assert!(standalone_routes.contains("POST               /refunds"));
    }

    #[test]
    fn init_rolls_back_when_a_write_fails_partway_through() {
        let dir = temp_dir("init-rollback");
        write_express_app(&dir);
        let original = std::fs::read_to_string(dir.join("src/server.js")).unwrap();

        std::fs::write(dir.join(".authboundry-fail-after-write"), "").unwrap();
        let error = run_with(&["init", dir.to_str().unwrap(), "--yes"]).unwrap_err();

        assert!(error.message.contains("simulated initialization failure"));
        assert_eq!(
            std::fs::read_to_string(dir.join("src/server.js")).unwrap(),
            original
        );
        assert!(!dir.join("authboundry.toml").exists());
        assert!(!dir.join(".authboundry/adoption.json").exists());
    }

    #[test]
    fn standalone_init_creates_equivalent_adoption_metadata_without_source_rewrite() {
        let dir = temp_dir("init-standalone");
        write_express_app(&dir);

        let applied = run_with(&["init", dir.to_str().unwrap(), "--standalone", "--yes"])
            .unwrap()
            .text;
        assert!(applied.contains("AuthBoundry adoption complete."));
        let server = std::fs::read_to_string(dir.join("src/server.js")).unwrap();
        assert!(!server.contains("authboundry()"));
        let manifest = std::fs::read_to_string(dir.join(".authboundry/adoption.json")).unwrap();
        assert!(manifest.contains("\"mode\": \"standalone\""));
    }

    #[test]
    fn attach_records_a_real_reachable_upstream_and_status_stays_truthful() {
        use std::io::Write;
        use std::net::TcpListener;

        let dir = temp_dir("attach-upstream");
        write_express_app(&dir);
        run_with(&["init", dir.to_str().unwrap(), "--yes"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let accepts = std::thread::spawn(move || {
            // Planning, atomic apply, status and boundary verification each
            // use the exact configured localhost origin.
            for _ in 0..5 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    );
                }
            }
        });
        let upstream = format!("http://localhost:{}", address.port());
        let attached = init::attach(&[
            dir.to_string_lossy().to_string(),
            "--upstream".to_string(),
            upstream.clone(),
            "--yes".to_string(),
        ])
        .unwrap()
        .text;
        assert!(attached.contains("Application attached."));
        let status = init::status(&[
            dir.to_string_lossy().to_string(),
            "--server".to_string(),
            "http://127.0.0.1:1".to_string(),
        ])
        .unwrap()
        .text;
        assert!(
            status.contains(&format!("✓ upstream {}", upstream)),
            "{}",
            status
        );
        assert!(status.contains("Runtime:\n  stopped"));
        assert!(status.contains("Protection:\n  not active"));
        let inspected = run_with(&["inspect", dir.join("authboundry.toml").to_str().unwrap()])
            .unwrap()
            .text;
        assert!(inspected.contains(&format!("upstream: {}", upstream)));
        let verified = init::verify(&[
            dir.to_string_lossy().to_string(),
            "--server".to_string(),
            "http://127.0.0.1:1".to_string(),
        ])
        .unwrap()
        .text;
        assert!(verified.contains(&format!("Upstream:\n  {}", upstream)));
        assert!(verified.contains("Connectivity:\n  ✓ reachable"));
        assert!(verified.contains("Application response:\n  ✓ received"));
        assert!(verified.contains("Runtime protection:\n  ○ inactive"));
        accepts.join().unwrap();
    }
}
