//! The inspection surface: the beginning of the Studio experience.
//!
//! An auth contract is inspectable as data, so what the platform generated is
//! reviewable in the same way as any other part of an application.

use std::path::PathBuf;

use appport_auth_mesh_dsl::{parse_auth_block, AuthConfig};
use appport_auth_mesh_providers::ConnectorRegistry;
use appport_auth_mesh_surface::{render_json_with, render_text, AuthSurface};

pub mod serve;

pub const USAGE: &str = "\
authport — the AuthPort authority boundary

USAGE:
    authport inspect [FILE] [--json] [--mode embedded|standalone]
    authport fingerprint [FILE]
    authport routes [FILE]
    authport providers [FILE]
    authport serve [FILE] [options]

SERVE OPTIONS:
    --addr ADDRESS              listen address (default 127.0.0.1:8787)
    --tenant NAME               a tenant to serve (repeatable)
    --account USER:PASS:CLAIMS  seed a principal, e.g. alice:secret:role=owner@acme
    --grant CAPABILITY=CLAIM:V  grant a capability, e.g. invoice.read=role:owner
    --upstream ADDRESS          the application AuthPort sits in front of
    --public PATH               forward this path prefix without a session
    --require PATH=CAPABILITY   require a capability for this path prefix

FILE defaults to the first of authport.toml, appport.auth, appport.toml or
auth.appport that exists in the current directory.
";

/// Candidate declaration files, in the order they are tried.
pub const DEFAULT_FILES: &[&str] = &[
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
    let mut command = None;
    let mut file: Option<PathBuf> = None;
    let mut json = false;
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
    let path = resolve_file(file)?;
    let source = std::fs::read_to_string(&path)
        .map_err(|err| error(format!("cannot read `{}`: {}", path.display(), err)))?;
    let config = parse_auth_block(&source)
        .map_err(|err| error(format!("{}: {}", path.display(), err.message)))?;

    let text = match command.as_str() {
        "inspect" => describe(&config, json, mode.as_deref()),
        "fingerprint" => format!(
            "contract {}\nsurface  {}\n",
            config.fingerprint(),
            AuthSurface::derive(&config).fingerprint()
        ),
        "routes" => AuthSurface::derive(&config)
            .routes
            .iter()
            .map(|route| {
                let methods = route
                    .methods
                    .iter()
                    .map(|method| method.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{:<18} {}\n", methods, route.path)
            })
            .collect(),
        "providers" => describe_providers(&config)?,
        "serve" => return run_server(config, &serve_options),
        other => return Err(error(format!("unknown command `{}`\n\n{}", other, USAGE))),
    };

    Ok(Output { text })
}

/// Start the standalone runtime and block until the process is stopped.
fn run_server(config: AuthConfig, options: &serve::ServeOptions) -> Result<Output, CliError> {
    let running = serve::start(config, options)?;
    let address = running.authport.address();

    println!("AuthPort listening on http://{} (standalone)", address);
    println!("  sign in           http://{}/auth/login", address);
    println!("  session           http://{}/auth/session", address);
    println!("  providers         http://{}/auth/providers", address);
    println!("  tenants           {}", running.tenants.join(", "));
    match &running.upstream {
        Some(upstream) => println!("  application       {}", upstream),
        None => println!("  application       (none: serving the auth surface only)"),
    }

    running.authport.wait();
    Ok(Output {
        text: String::new(),
    })
}

fn describe(config: &AuthConfig, json: bool, mode: Option<&str>) -> String {
    let surface = AuthSurface::derive(config);
    if !json {
        return render_text(&surface);
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
        assert!(json.contains("\"boundary\": {\"contract\": \"authport.boundary/v1\""));
        assert!(json.contains("\"modes\": [\"embedded\", \"standalone\"]"));
        assert!(json.contains("\"session_credential\": \"cookie:authport_session\""));
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

        let running = serve::start(config, &options).expect("AuthPort binds");
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
            cookie_value(&signed_in, "authport_session").expect("a session cookie is issued");

        let granted = send(
            address,
            &ClientRequest::post_json("/auth/authorize", "{\"capability\": \"invoice.read\"}")
                .with_cookie("authport_session", &credential),
        )
        .unwrap();
        assert!(granted.body_string().contains("\"allowed\": true"));

        let refused = send(
            address,
            &ClientRequest::post_json("/auth/authorize", "{\"capability\": \"billing.charge\"}")
                .with_cookie("authport_session", &credential),
        )
        .unwrap();
        assert!(refused.body_string().contains("\"allowed\": false"));

        running.authport.shutdown();
    }
}
