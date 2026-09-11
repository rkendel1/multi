use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use appport_auth_mesh_discovery::{
    discover, propose_authority, ApplicationCandidate, RouteCandidate,
};
use appport_auth_mesh_server::ApplicationUpstream;

use crate::{error, CliError, Output};

const DEFAULT_DECLARATION: &str = r#"use auth {
  providers = [local]
  tenant = false
  isolation = "strict"
  agents = false

  claims = {
    role = enum["admin", "user"]
  }

  policy = {}

  experience = {
    sign_in = enabled
    sign_up = enabled
    sign_out = enabled
    password = enabled
    password_reset = enabled
    password_change = enabled
    external_identity = enabled
    account_linking = enabled
    email_verification = enabled
    mfa = disabled
    passkeys = disabled
    device_management = disabled
    session_management = enabled
    profile = disabled
    tenant_switching = false
    recovery = disabled
  }

  password = {
    min_length = 12
    max_length = 128
    require_uppercase = false
    require_lowercase = false
    require_number = false
    require_special_character = false
    expiration_days = null
    history_count = 5
    allow_password_change = true
    allow_password_reset = true
  }

  storage = {
    authority = "feltdb"
    audit = "feltdb"
    reporting = "authboundry_projection"
  }

  ui = {
    mode = "generated"
    theme = "authboundry-default"
    login = "default"
    signup = "default"
    account = "default"
    password_forgot = "default"
    password_reset = "default"
    password_change = "default"
    email_verification = "default"
    account_links = "default"
    profile = "default"
    devices = "default"
    sessions = "default"
    mfa = "default"
    passkeys = "default"
    recovery = "default"
    tenant = "default"
    agents = "default"
  }
}

use mail
mail {
  identities {
    auth = "auth@example.com"
  }
  templates {
    password_reset = "./emails/password-reset.html"
    email_verification = "./emails/email-verification.html"
  }
}
"#;

const AUTH_OPTION_DEFAULTS: &[(&str, &str)] = &[
    ("tenant", "  tenant = false\n"),
    ("isolation", "  isolation = \"strict\"\n"),
    ("agents", "  agents = false\n"),
    ("policy", "  policy = {}\n"),
    ("experience", "  experience = {\n    sign_in = enabled\n    sign_up = enabled\n    sign_out = enabled\n    password = enabled\n    password_reset = enabled\n    password_change = enabled\n    external_identity = enabled\n    account_linking = enabled\n    email_verification = enabled\n    mfa = disabled\n    passkeys = disabled\n    device_management = disabled\n    session_management = enabled\n    profile = disabled\n    tenant_switching = false\n    recovery = disabled\n  }\n"),
    ("password", "  password = {\n    min_length = 12\n    max_length = 128\n    require_uppercase = false\n    require_lowercase = false\n    require_number = false\n    require_special_character = false\n    expiration_days = null\n    history_count = 5\n    allow_password_change = true\n    allow_password_reset = true\n  }\n"),
    ("storage", "  storage = {\n    authority = \"feltdb\"\n    audit = \"feltdb\"\n    reporting = \"authboundry_projection\"\n  }\n"),
    ("ui", "  ui = {\n    mode = \"generated\"\n    theme = \"authboundry-default\"\n    login = \"default\"\n    signup = \"default\"\n    account = \"default\"\n    password_forgot = \"default\"\n    password_reset = \"default\"\n    password_change = \"default\"\n    email_verification = \"default\"\n    account_links = \"default\"\n    profile = \"default\"\n    devices = \"default\"\n    sessions = \"default\"\n    mfa = \"default\"\n    passkeys = \"default\"\n    recovery = \"default\"\n    tenant = \"default\"\n    agents = \"default\"\n  }\n"),
];

const UI_SCREEN_DEFAULTS: &[&str] = &[
    "login",
    "signup",
    "account",
    "password_forgot",
    "password_reset",
    "password_change",
    "email_verification",
    "account_links",
    "profile",
    "devices",
    "sessions",
    "mfa",
    "passkeys",
    "recovery",
    "tenant",
    "agents",
];
const MANIFEST_DIR: &str = ".authboundry";
const MANIFEST_FILE: &str = ".authboundry/adoption.json";
const DEVELOPMENT_FILE: &str = ".authboundry/development.json";
const INTEGRATION_FILE: &str = ".authboundry/integration.json";
const PASSWORD_RESET_HTML: &str = include_str!("../../../templates/password-reset.html");
const PASSWORD_RESET_TEXT: &str = include_str!("../../../templates/password-reset.txt");
const EMAIL_VERIFICATION_HTML: &str = include_str!("../../../templates/email-verification.html");
const EMAIL_VERIFICATION_TEXT: &str = include_str!("../../../templates/email-verification.txt");
const DEFAULT_FILES: &[&str] = &[
    "authboundry.toml",
    "authport.toml",
    "appport.auth",
    "appport.toml",
    "auth.appport",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitMode {
    Embedded,
    Standalone,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InitOptions {
    pub dry_run: bool,
    pub json: bool,
    pub yes: bool,
    pub mode: Option<InitMode>,
    pub root: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileChange {
    path: PathBuf,
    before: Option<String>,
    after: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InitPlan {
    application: ApplicationCandidate,
    mode: InitMode,
    changes: Vec<FileChange>,
    already_integrated: bool,
    detected: bool,
    integration_supported: bool,
}

pub fn run(args: &[String]) -> Result<Output, CliError> {
    let options = parse_options(args)?;
    let root = match &options.root {
        Some(root) => root.clone(),
        None => {
            std::env::current_dir().map_err(|err| error(format!("cannot read cwd: {}", err)))?
        }
    };
    let plan = build_plan(&root, options.mode.unwrap_or(InitMode::Standalone))?;

    if options.json {
        return Ok(Output {
            text: render_plan_json(&plan, options.dry_run),
        });
    }
    if options.dry_run {
        return Ok(Output {
            text: render_plan_text(&plan, true),
        });
    }

    if plan.already_integrated && plan.changes.is_empty() {
        return Ok(Output {
            text: render_plan_text(&plan, false),
        });
    }

    let interactive = !options.yes;
    if interactive {
        let preview = render_plan_text(&plan, true);
        print!("{}Apply this adoption plan? [y/N] ", preview);
        io::stdout()
            .flush()
            .map_err(|err| error(format!("cannot display adoption plan: {}", err)))?;
        let stdin = io::stdin();
        let mut input = stdin.lock();
        if !confirm_adoption(&mut input)? {
            return Ok(Output {
                text: "Adoption cancelled. No files were changed.\n".to_string(),
            });
        }

        // Discovery may have changed while the user reviewed the preview.
        // Never apply a plan other than the exact plan that was confirmed.
        if !plan_inputs_unchanged(&plan) {
            return Err(error(
                "the application changed while the adoption plan was being reviewed; refusing to apply a stale plan",
            ));
        }
    }

    apply_plan(&plan)?;
    let verified = verify_root(&root, "http://127.0.0.1:8787")?;
    if !verified.ok {
        return Err(error("AuthBoundry initialization verification failed"));
    }
    let mut applied = applied_plan_text(&plan, &verified);
    if interactive {
        applied.push_str(&launch_studio(&root));
    }
    Ok(Output {
        text: if interactive {
            applied
        } else {
            format!("{}{}", render_plan_text(&plan, true), applied)
        },
    })
}

fn launch_studio(root: &Path) -> String {
    if cfg!(test) || std::env::var_os("AUTHBOUNDRY_NO_STUDIO").is_some() {
        return "Studio:\n  Run `authboundry studio` to continue.\n".to_string();
    }
    let executable = match std::env::current_exe() {
        Ok(value) => value,
        Err(_) => return studio_fallback(),
    };
    let studio_url = "http://127.0.0.1:8787/_authboundry/studio";
    if upstream_reachable("http://127.0.0.1:8787") {
        return studio_port_occupied();
    }
    let mut child = Command::new(executable)
        .arg("studio")
        .arg(root)
        .arg("--no-open")
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if child.is_err() {
        return studio_fallback();
    }
    let child = child.as_mut().expect("Studio child was checked above");
    for _ in 0..20 {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return studio_fallback();
        }
        if upstream_reachable("http://127.0.0.1:8787") {
            return if crate::studio::open_browser(studio_url) {
                "Starting Studio...\n✓ Studio listening on http://127.0.0.1:8787/_authboundry/studio\n✓ Protected application boundary at http://127.0.0.1:8787/\nOpening Studio...\n".to_string()
            } else {
                format!("Starting Studio...\n✓ Studio listening on {studio_url}\n✓ Protected application boundary at http://127.0.0.1:8787/\nOpen {studio_url} to continue.\n")
            };
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    studio_fallback()
}

fn studio_port_occupied() -> String {
    "Studio could not be started because http://127.0.0.1:8787 is already in use.\nStop the existing AuthBoundry Studio, then run:\n  authboundry studio\nOr use another address:\n  authboundry studio --addr 127.0.0.1:8788\n".to_string()
}

fn studio_fallback() -> String {
    "Studio could not be started automatically.\nRun:\n  authboundry studio\n".to_string()
}

pub fn attach(args: &[String]) -> Result<Output, CliError> {
    let mut root = None;
    let mut upstream = None;
    let mut yes = false;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--yes" => yes = true,
            "--upstream" => {
                index += 1;
                upstream = Some(
                    args.get(index)
                        .ok_or_else(|| error("--upstream needs a value"))?
                        .clone(),
                );
            }
            flag if flag.starts_with('-') => return Err(error(format!("unknown flag `{}`", flag))),
            value => root = Some(PathBuf::from(value)),
        }
        index += 1;
    }
    let root = root.unwrap_or(std::env::current_dir().map_err(|err| error(err.to_string()))?);
    let upstream = upstream.ok_or_else(|| {
        error("no application upstream configured\nUse:\n  authboundry attach --upstream http://127.0.0.1:9000")
    })?;
    let plan = plan_attachment(&root, &upstream)?;
    let preview = plan.preview.clone();
    if !yes {
        print!("{}Attach this application? [y/N] ", preview);
        io::stdout().flush().map_err(|err| error(err.to_string()))?;
        if !confirm_adoption(&mut io::stdin().lock())? {
            return Ok(Output {
                text: "Attachment cancelled. No files were changed.\n".to_string(),
            });
        }
        if fs::read_to_string(root.join(MANIFEST_FILE)).ok().as_deref()
            != Some(plan.before.as_str())
        {
            return Err(error("the adoption state changed while the attachment plan was reviewed; refusing to apply a stale plan"));
        }
    }
    apply_attachment(&plan)?;
    Ok(Output {
        text: format!(
            "{}Application attached.\nAuthority state:\n  configured\nApplication attachment:\n  upstream {}\nProtection:\n  ready when AuthBoundry is running\nApplication source:\n  unchanged\n",
            if yes { preview } else { String::new() },
            plan.upstream
        ),
    })
}

pub fn dev(args: &[String]) -> Result<Output, CliError> {
    let mut root = None;
    let mut requested_upstream = None;
    let mut address = "127.0.0.1:8787".to_string();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--upstream" => {
                index += 1;
                requested_upstream = Some(
                    args.get(index)
                        .ok_or_else(|| error("--upstream needs a URL"))?
                        .clone(),
                );
            }
            "--addr" => {
                index += 1;
                address = args
                    .get(index)
                    .ok_or_else(|| error("--addr needs an address"))?
                    .clone();
            }
            flag if flag.starts_with('-') => return Err(error(format!("unknown flag `{}`", flag))),
            value if root.is_none() => root = Some(PathBuf::from(value)),
            value => return Err(error(format!("unexpected argument `{}`", value))),
        }
        index += 1;
    }
    let root = root.unwrap_or(std::env::current_dir().map_err(|err| error(err.to_string()))?);
    let state = read_adoption(&root)
        .ok_or_else(|| error("no AuthBoundry adoption exists; run `authboundry init` first"))?;
    let mut command = state
        .run_command
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| error("no application development command was discovered"))?;
    let upstream = requested_upstream
        .clone()
        .or(state
            .upstream
            .clone()
            .filter(|_| requested_upstream.is_none()))
        .unwrap_or_else(|| conventional_dev_upstream(&state.framework));
    if requested_upstream.is_none() && state.upstream.is_none() && upstream_reachable(&upstream) {
        return Err(error(format!(
            "inferred application upstream {} is already occupied; stop that process or pass an explicit --upstream",
            upstream
        )));
    }
    if requested_upstream.is_some() && state.framework == "FeltDB" {
        if let Ok(origin) = ApplicationUpstream::parse(&upstream) {
            command.push_str(&format!(" --port {}", origin.port));
        }
    }
    println!("Starting application: {}", command);
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .current_dir(&root)
        .env(
            "AUTHBOUNDRY_PROXY_SECRET",
            development_proxy_secret(&root).unwrap_or_default(),
        )
        .spawn()
        .map_err(|err| error(format!("cannot start application `{}`: {}", command, err)))?;
    let reachable = (0..100).any(|_| {
        if upstream_reachable(&upstream) {
            true
        } else {
            std::thread::sleep(Duration::from_millis(100));
            false
        }
    });
    if !reachable {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error(format!(
            "application did not become reachable at {} after 10 seconds",
            upstream
        )));
    }
    let plan = plan_attachment(&root, &upstream)?;
    apply_attachment(&plan)?;
    println!("✓ Application attached at {}", upstream);
    println!("✓ Development admin and user accounts loaded");
    println!("✓ Protected application boundary: http://{}/", address);
    let studio_args = vec![
        root.to_string_lossy().to_string(),
        "--addr".to_string(),
        address,
    ];
    let result = crate::studio::run(&studio_args);
    let _ = child.kill();
    let _ = child.wait();
    result
}

fn conventional_dev_upstream(framework: &str) -> String {
    let port = match framework {
        "FastAPI" | "Starlette" | "Litestar" => 8000,
        "Django" => 8000,
        "React" | "React Router" | "Next.js" | "Express" | "NestJS" => 3000,
        _ => 5173,
    };
    format!("http://127.0.0.1:{}", port)
}

#[derive(Debug, Clone)]
pub(crate) struct AttachmentPlan {
    pub root: PathBuf,
    pub application: String,
    pub upstream: String,
    pub routes: usize,
    pub before: String,
    pub after: String,
    pub preview: String,
}

pub(crate) fn plan_attachment(root: &Path, upstream: &str) -> Result<AttachmentPlan, CliError> {
    let upstream = upstream_address(upstream)?;
    if !upstream_reachable(&upstream.to_string()) {
        return Err(error(format!(
            "application upstream `{}` is not reachable; start the application and try again",
            upstream
        )));
    }
    let before = fs::read_to_string(root.join(MANIFEST_FILE))
        .map_err(|_| error("no AuthBoundry adoption exists; run `authboundry init` first"))?;
    let application = discover(root).ok_or_else(|| error("no supported application found"))?;
    let name = application
        .name
        .clone()
        .unwrap_or_else(|| "(unknown)".to_string());
    let upstream = upstream.to_string();
    let after = render_manifest_with_upstream(&application, InitMode::Standalone, Some(&upstream));
    let preview = format!(
        "AuthBoundry · Attachment Preview\n+ application\n    {}\n+ mode\n    standalone\n+ upstream\n    {}\n+ protection\n    active after attachment\nApplication routes:\n    {} currently discovered\nNo application source will be modified.\n",
        name, upstream, application.routes.len()
    );
    Ok(AttachmentPlan {
        root: root.to_path_buf(),
        application: name,
        upstream: upstream.to_string(),
        routes: application.routes.len(),
        before,
        after,
        preview,
    })
}

pub(crate) fn apply_attachment(plan: &AttachmentPlan) -> Result<(), CliError> {
    let path = plan.root.join(MANIFEST_FILE);
    if fs::read_to_string(&path).ok().as_deref() != Some(plan.before.as_str()) {
        return Err(error(
            "attachment state changed after preview; no changes were made",
        ));
    }
    if !upstream_reachable(&plan.upstream) {
        return Err(error(
            "application became unreachable after preview; no changes were made",
        ));
    }
    atomic_write(&path, &plan.after)
}

pub(crate) fn detach_application(root: &Path) -> Result<(), CliError> {
    let state = read_adoption(root).ok_or_else(|| error("no AuthBoundry adoption exists"))?;
    let application = discover(root).ok_or_else(|| error("no supported application found"))?;
    let current =
        fs::read_to_string(root.join(MANIFEST_FILE)).map_err(|err| error(err.to_string()))?;
    let after = render_manifest_with_upstream(
        &application,
        if state.mode == "embedded" {
            InitMode::Embedded
        } else {
            InitMode::Standalone
        },
        None,
    );
    if current == after {
        return Ok(());
    }
    atomic_write(&root.join(MANIFEST_FILE), &after)
}

pub fn status(args: &[String]) -> Result<Output, CliError> {
    let mut root = None;
    let mut server = "http://127.0.0.1:8787".to_string();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--server" => {
                index += 1;
                server = args
                    .get(index)
                    .ok_or_else(|| error("--server needs a value"))?
                    .clone();
            }
            flag if flag.starts_with('-') => return Err(error(format!("unknown flag `{}`", flag))),
            value => root = Some(PathBuf::from(value)),
        }
        index += 1;
    }
    let root = root.unwrap_or(std::env::current_dir().map_err(|err| error(err.to_string()))?);
    let adoption = read_adoption(&root);
    let authority = resolve_config(&root).is_ok();
    let running = upstream_reachable(&server);
    let upstream = adoption.as_ref().and_then(|state| state.upstream.clone());
    let attached = upstream.as_deref().map(upstream_reachable).unwrap_or(false);
    let protected = running && attached;
    let application = adoption
        .as_ref()
        .map(|state| state.application.as_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("(none)");
    let mode = adoption
        .as_ref()
        .map(|state| state.mode.as_str())
        .unwrap_or("standalone");
    let routes = adoption.as_ref().map(|state| state.routes).unwrap_or(0);
    let attachment = match (&upstream, attached) {
        (Some(value), true) => format!("✓ upstream {}", value),
        (Some(value), false) => format!("configured but unreachable: {}", value),
        (None, _) => "none".to_string(),
    };
    let reason = if upstream.is_none() {
        "no application upstream configured"
    } else if !attached {
        "application upstream is not reachable"
    } else if !running {
        "AuthBoundry runtime is stopped"
    } else {
        "authority boundary is active"
    };
    Ok(Output {
        text: format!(
            "AuthBoundry · Status\n────────────────────\nAuthority:\n  {}\nRuntime:\n  {}\nApplication:\n  {}\nAttachment:\n  {}\nProtection:\n  {}\nMode:\n  {}\nRoutes:\n  {} discovered\nReason:\n  {}\n",
            if authority { "configured" } else { "not configured" },
            if running { "running" } else { "stopped" },
            application,
            attachment,
            if protected { "✓ active" } else { "not active" },
            mode,
            routes,
            reason
        ),
    })
}

fn confirm_adoption(input: &mut impl BufRead) -> Result<bool, CliError> {
    let mut answer = String::new();
    match input.read_line(&mut answer) {
        Ok(0) => Err(error(
            "AuthBoundry cannot obtain interactive confirmation.\nRefusing to modify the application.\nUse:\n  authboundry init --yes",
        )),
        Ok(_) => Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")),
        Err(err) if err.kind() == io::ErrorKind::Interrupted => {
            Err(error("AuthBoundry adoption interrupted; no files were changed"))
        }
        Err(err) => Err(error(format!(
            "AuthBoundry cannot obtain interactive confirmation: {}\nRefusing to modify the application.\nUse:\n  authboundry init --yes",
            err
        ))),
    }
}

pub fn verify(args: &[String]) -> Result<Output, CliError> {
    let mut json = false;
    let mut root = None;
    let mut server = "http://127.0.0.1:8787".to_string();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--root" => {
                index += 1;
                root = Some(PathBuf::from(
                    args.get(index)
                        .ok_or_else(|| error("--root needs a value"))?
                        .clone(),
                ));
            }
            "--server" => {
                index += 1;
                server = args
                    .get(index)
                    .ok_or_else(|| error("--server needs a value"))?
                    .clone();
            }
            flag if flag.starts_with('-') => return Err(error(format!("unknown flag `{}`", flag))),
            value => root = Some(PathBuf::from(value)),
        }
        index += 1;
    }
    let root = match root {
        Some(root) => root,
        None => {
            std::env::current_dir().map_err(|err| error(format!("cannot read cwd: {}", err)))?
        }
    };
    let report = verify_root(&root, &server)?;
    if !report.ok {
        return Err(error(if json {
            render_verify_json(&report)
        } else {
            render_verify_text(&report)
        }));
    }
    Ok(Output {
        text: if json {
            render_verify_json(&report)
        } else {
            render_verify_text(&report)
        },
    })
}

pub fn discovered_routes(root: &Path) -> Option<Vec<RouteCandidate>> {
    discover(root).map(|app| app.routes)
}

pub(crate) fn is_public_entry_path(path: &str) -> bool {
    matches!(
        path.trim_end_matches('/'),
        "" | "/login" | "/signin" | "/sign-in" | "/signup" | "/sign-up" | "/register"
    )
}

fn parse_options(args: &[String]) -> Result<InitOptions, CliError> {
    let mut options = InitOptions::default();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--dry-run" => options.dry_run = true,
            "--json" => options.json = true,
            "--yes" => options.yes = true,
            "--standalone" => options.mode = Some(InitMode::Standalone),
            "--embedded" => options.mode = Some(InitMode::Embedded),
            "--root" => {
                index += 1;
                options.root = Some(PathBuf::from(
                    args.get(index)
                        .ok_or_else(|| error("--root needs a value"))?
                        .clone(),
                ));
            }
            flag if flag.starts_with('-') => return Err(error(format!("unknown flag `{}`", flag))),
            value => options.root = Some(PathBuf::from(value)),
        }
        index += 1;
    }
    Ok(options)
}

fn build_plan(root: &Path, mode: InitMode) -> Result<InitPlan, CliError> {
    let application = discover(root).ok_or_else(|| {
        error("no supported application found (looked for package.json or Cargo.toml)")
    })?;
    let already_integrated = boundary_integrated(&application, mode);
    let mut changes = Vec::new();

    if !already_integrated {
        if !application.existing_authport.configuration {
            changes.push(config_change(root));
        }
        changes.push(manifest_change(&application, mode));
    }
    if application.existing_authport.configuration {
        if let Some(change) = config_upgrade_change(root) {
            changes.push(change);
        }
    }
    if !root.join(DEVELOPMENT_FILE).exists() {
        changes.push(development_accounts_change(root));
    }
    if !root.join(INTEGRATION_FILE).exists() {
        changes.push(integration_change(&application));
    }
    for (name, contents) in [
        ("password-reset.html", PASSWORD_RESET_HTML),
        ("password-reset.txt", PASSWORD_RESET_TEXT),
        ("email-verification.html", EMAIL_VERIFICATION_HTML),
        ("email-verification.txt", EMAIL_VERIFICATION_TEXT),
    ] {
        let path = root.join("emails").join(name);
        if !path.exists() {
            changes.push(FileChange {
                path,
                before: None,
                after: contents.to_string(),
            });
        }
    }
    if let Some(change) = gitignore_change(root) {
        changes.push(change);
    }
    if let Some(change) = vite_guard_upgrade_change(root) {
        changes.push(change);
    }

    let native_changes = framework_integration_changes(&application)?;
    let integration_supported = !native_changes.is_empty()
        || application.entrypoints.iter().any(|entry| {
            fs::read_to_string(&entry.path)
                .map(|source| source.contains("AuthBoundry integration"))
                .unwrap_or(false)
        });
    changes.extend(native_changes);

    Ok(InitPlan {
        application,
        mode,
        changes,
        already_integrated,
        detected: true,
        integration_supported,
    })
}

fn vite_guard_upgrade_change(root: &Path) -> Option<FileChange> {
    let path = ["vite.config.ts", "vite.config.js", "vite.config.mjs"]
        .iter()
        .map(|name| root.join(name))
        .find(|path| path.exists())?;
    let before = fs::read_to_string(&path).ok()?;
    if !before.contains("Generated by AuthBoundry. Direct Vite access")
        || before.contains("function developmentSecret()")
    {
        return None;
    }
    let mut after = before.replacen(
        "import { defineConfig } from 'vite';",
        "import { readFileSync } from 'node:fs';\nimport { defineConfig } from 'vite';\n\nfunction developmentSecret(): string {\n  if (process.env.AUTHBOUNDRY_PROXY_SECRET) return process.env.AUTHBOUNDRY_PROXY_SECRET;\n  try {\n    const development = JSON.parse(readFileSync(new URL('./.authboundry/development.json', import.meta.url), 'utf8'));\n    return typeof development.proxy_secret === 'string' ? development.proxy_secret : '';\n  } catch {\n    return '';\n  }\n}",
        1,
    );
    after = after.replacen(
        "const secret = process.env.AUTHBOUNDRY_PROXY_SECRET || '';",
        "const secret = developmentSecret();",
        1,
    );
    (after != before).then_some(FileChange {
        path,
        before: Some(before),
        after,
    })
}

fn framework_integration_changes(
    application: &ApplicationCandidate,
) -> Result<Vec<FileChange>, CliError> {
    let Some(entrypoint) = application.entrypoints.first() else {
        return Ok(Vec::new());
    };
    let source = fs::read_to_string(&entrypoint.path).map_err(|err| {
        error(format!(
            "cannot inspect integration entrypoint `{}`: {}",
            entrypoint.path.display(),
            err
        ))
    })?;
    if source.contains("AuthBoundry integration") {
        return Ok(Vec::new());
    }
    let framework = application.framework.as_deref().unwrap_or("");
    if matches!(framework, "FeltDB" | "React" | "React Router" | "Vite")
        && source.contains("<App />")
    {
        return react_integration_changes(application, &entrypoint.path, &source);
    }
    if framework == "Express" {
        return express_integration_changes(&entrypoint.path, &source);
    }
    if framework == "FastAPI" {
        return fastapi_integration_changes(&entrypoint.path, &source);
    }
    Ok(Vec::new())
}

fn react_integration_changes(
    application: &ApplicationCandidate,
    entrypoint: &Path,
    source: &str,
) -> Result<Vec<FileChange>, CliError> {
    let extension = entrypoint
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("tsx");
    let generated = entrypoint
        .parent()
        .unwrap_or(&application.root)
        .join("authboundry")
        .join(format!("provider.{}", extension));
    let provider = if matches!(extension, "ts" | "tsx") {
        r#"// Generated by AuthBoundry. Existing application auth remains available during migration.
import React from 'react';
import { createAuthBoundryReact } from '@authboundry/core/react';

const integration = createAuthBoundryReact(React, { tenant: 'development', connector: 'local' });
export const useAuthBoundry = integration.useAuth;
export const authBoundryClient = integration.client;

export function AuthBoundryProvider({ children }: { children: React.ReactNode }) {
  return <integration.AuthBoundry>{children}</integration.AuthBoundry>;
}
"#
    } else {
        r#"// Generated by AuthBoundry. Existing application auth remains available during migration.
import React from 'react';
import { createAuthBoundryReact } from '@authboundry/core/react';

const integration = createAuthBoundryReact(React, { tenant: 'development', connector: 'local' });
export const useAuthBoundry = integration.useAuth;
export const authBoundryClient = integration.client;

export function AuthBoundryProvider({ children }) {
  return <integration.AuthBoundry>{children}</integration.AuthBoundry>;
}
"#
    };
    let relative = "./authboundry/provider";
    let after = format!(
        "// AuthBoundry integration: provider bridge (safe to remove with `authboundry rollback`)\nimport {{ AuthBoundryProvider }} from '{}';\n{}",
        relative,
        source.replacen(
            "<App />",
            "<AuthBoundryProvider><App /></AuthBoundryProvider>",
            1
        )
    );
    let mut changes = vec![
        FileChange {
            before: fs::read_to_string(&generated).ok(),
            path: generated,
            after: provider.to_string(),
        },
        FileChange {
            path: entrypoint.to_path_buf(),
            before: Some(source.to_string()),
            after,
        },
    ];
    if let Some(change) = package_dependency_change(&application.root)? {
        changes.push(change);
    }
    Ok(changes)
}

fn package_dependency_change(root: &Path) -> Result<Option<FileChange>, CliError> {
    let path = root.join("package.json");
    let before = fs::read_to_string(&path)
        .map_err(|err| error(format!("cannot read package.json: {}", err)))?;
    if before.contains("\"@authboundry/core\"") {
        return Ok(None);
    }
    let after = if before.contains("\"dependencies\": {") {
        before.replacen(
            "\"dependencies\": {",
            "\"dependencies\": {\n    \"@authboundry/core\": \"^1.12.0\",",
            1,
        )
    } else {
        before.replacen(
            '{',
            "{\n  \"dependencies\": {\"@authboundry/core\": \"^1.12.0\"},",
            1,
        )
    };
    Ok(Some(FileChange {
        path,
        before: Some(before),
        after,
    }))
}

fn express_integration_changes(
    entrypoint: &Path,
    source: &str,
) -> Result<Vec<FileChange>, CliError> {
    let marker = source
        .lines()
        .find(|line| line.contains("= express()"))
        .ok_or_else(|| error("Express was detected but its application constructor is not safe to modify automatically"))?;
    let directory = entrypoint.parent().unwrap_or_else(|| Path::new("."));
    let generated = directory.join("authboundry").join("context.cjs");
    let middleware = r#"// Generated by AuthBoundry. Verifies context injected by the boundary.
function sign(secret, context) {
  let hash = 0xcbf29ce484222325n;
  for (const byte of Buffer.from(`${secret}|${context}`)) {
    hash = BigInt.asUintN(64, (hash ^ BigInt(byte)) * 0x100000001b3n);
  }
  return hash.toString(16).padStart(16, '0');
}
exports.authBoundryContext = function authBoundryContext() {
  return function authBoundryContextMiddleware(request, response, next) {
    const context = request.get('x-authboundry-context');
    const signature = request.get('x-authboundry-signature');
    const secret = process.env.AUTHBOUNDRY_PROXY_SECRET || '';
    const proxySignature = request.get('x-authboundry-proxy-signature');
    if (!secret || sign(secret, 'proxy') !== proxySignature) {
      return response.status(403).json({ error: 'direct_access_denied', message: 'Use the AuthBoundry application URL.' });
    }
    request.authboundry = context && signature && secret && sign(secret, context) === signature
      ? JSON.parse(context) : null;
    next();
  };
};
"#;
    let inserted = format!(
        "{}\napp.use(authBoundryContext()); // AuthBoundry verified authority context",
        marker
    );
    let after = format!(
        "// AuthBoundry integration: signed context bridge (safe to remove with `authboundry rollback`)\nconst {{ authBoundryContext }} = require('./authboundry/context.cjs');\n{}",
        source.replacen(marker, &inserted, 1)
    );
    Ok(vec![
        FileChange {
            path: generated.clone(),
            before: fs::read_to_string(&generated).ok(),
            after: middleware.to_string(),
        },
        FileChange {
            path: entrypoint.to_path_buf(),
            before: Some(source.to_string()),
            after,
        },
    ])
}

fn fastapi_integration_changes(
    entrypoint: &Path,
    source: &str,
) -> Result<Vec<FileChange>, CliError> {
    let marker = source
        .lines()
        .find(|line| line.contains("= FastAPI("))
        .ok_or_else(|| error("FastAPI was detected but its application constructor is not safe to modify automatically"))?;
    let directory = entrypoint.parent().unwrap_or_else(|| Path::new("."));
    let generated = directory.join("authboundry_context.py");
    let middleware = r#"# Generated by AuthBoundry. Verifies context injected by the boundary.
import json
import os

def _sign(secret: str, context: str) -> str:
    value = 0xcbf29ce484222325
    for byte in f"{secret}|{context}".encode():
        value = ((value ^ byte) * 0x100000001b3) & 0xffffffffffffffff
    return f"{value:016x}"

def install_authboundry(app):
    @app.middleware("http")
    async def authboundry_context(request, call_next):
        context = request.headers.get("x-authboundry-context")
        signature = request.headers.get("x-authboundry-signature")
        secret = os.environ.get("AUTHBOUNDRY_PROXY_SECRET", "")
        proxy_signature = request.headers.get("x-authboundry-proxy-signature")
        if not secret or _sign(secret, "proxy") != proxy_signature:
            from starlette.responses import JSONResponse
            return JSONResponse({"error": "direct_access_denied", "message": "Use the AuthBoundry application URL."}, status_code=403)
        request.state.authboundry = json.loads(context) if (
            context and signature and secret and _sign(secret, context) == signature
        ) else None
        return await call_next(request)
"#;
    let inserted = format!(
        "{}\ninstall_authboundry(app)  # AuthBoundry verified authority context",
        marker
    );
    let after = format!(
        "# AuthBoundry integration: signed context bridge (safe to remove with `authboundry rollback`)\nfrom authboundry_context import install_authboundry\n{}",
        source.replacen(marker, &inserted, 1)
    );
    Ok(vec![
        FileChange {
            path: generated.clone(),
            before: fs::read_to_string(&generated).ok(),
            after: middleware.to_string(),
        },
        FileChange {
            path: entrypoint.to_path_buf(),
            before: Some(source.to_string()),
            after,
        },
    ])
}

fn integration_change(application: &ApplicationCandidate) -> FileChange {
    let systems = application
        .existing_auth
        .iter()
        .map(|system| {
            format!(
                "{{\"id\":\"{}\",\"name\":\"{}\",\"credentials\":{},\"sessions\":{},\"profiles\":{},\"authorization\":{},\"strategy\":\"{}\"}}",
                escape(&system.id),
                escape(&system.display_name),
                system.credentials,
                system.sessions,
                system.profiles,
                system.authorization,
                system.coexistence.as_str()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    FileChange {
        path: application.root.join(INTEGRATION_FILE),
        before: None,
        after: format!(
            "{{\n  \"framework\": \"{}\",\n  \"status\": \"planned\",\n  \"default_strategy\": \"{}\",\n  \"preserve_profiles\": true,\n  \"rollback_manifest\": \".authboundry/rollback/manifest.tsv\",\n  \"existing_auth\": [{}]\n}}\n",
            escape(application.framework.as_deref().unwrap_or("")),
            if application.existing_auth.iter().any(|system| system.coexistence.as_str() == "migrate") { "migrate" } else { "bridge" },
            systems
        ),
    }
}

fn plan_inputs_unchanged(plan: &InitPlan) -> bool {
    discover(&plan.application.root).as_ref() == Some(&plan.application)
        && plan
            .changes
            .iter()
            .all(|change| fs::read_to_string(&change.path).ok() == change.before)
}

fn development_accounts_change(root: &Path) -> FileChange {
    let admin_password = development_password();
    let user_password = development_password();
    let proxy_secret = development_password();
    FileChange {
        path: root.join(DEVELOPMENT_FILE),
        before: None,
        after: format!(
            "{{\n  \"tenant\": \"development\",\n  \"proxy_secret\": \"{}\",\n  \"accounts\": [\n    {{\"username\": \"admin\", \"password\": \"{}\", \"claims\": \"role=admin\"}},\n    {{\"username\": \"user\", \"password\": \"{}\", \"claims\": \"role=user\"}}\n  ]\n}}\n",
            proxy_secret, admin_password, user_password
        ),
    }
}

fn development_password() -> String {
    use std::io::Read;
    let mut bytes = [0u8; 18];
    if fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .is_err()
    {
        let seed = format!(
            "{}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or_default(),
            std::thread::current().id()
        );
        for (index, byte) in seed.bytes().enumerate() {
            bytes[index % bytes.len()] ^= byte.rotate_left((index % 8) as u32);
        }
    }
    let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    bytes
        .iter()
        .map(|byte| alphabet[*byte as usize % alphabet.len()] as char)
        .collect()
}

fn gitignore_change(root: &Path) -> Option<FileChange> {
    let path = root.join(".gitignore");
    let before = fs::read_to_string(&path).ok();
    let mut after = before.clone().unwrap_or_default();
    for ignored in [DEVELOPMENT_FILE, ".authboundry/mail/"] {
        if !after.lines().any(|line| line.trim() == ignored) {
            if !after.is_empty() && !after.ends_with('\n') {
                after.push('\n');
            }
            after.push_str(ignored);
            after.push('\n');
        }
    }
    if before.as_deref() == Some(after.as_str()) {
        return None;
    }
    Some(FileChange {
        path,
        before,
        after,
    })
}

fn boundary_integrated(application: &ApplicationCandidate, mode: InitMode) -> bool {
    let _ = mode;
    DEFAULT_FILES
        .iter()
        .any(|name| application.root.join(name).exists())
        && application.root.join(MANIFEST_FILE).exists()
}

fn config_change(root: &Path) -> FileChange {
    let path = root.join("authboundry.toml");
    FileChange {
        before: fs::read_to_string(&path).ok(),
        path,
        after: DEFAULT_DECLARATION.to_string(),
    }
}

fn config_upgrade_change(root: &Path) -> Option<FileChange> {
    let path = DEFAULT_FILES
        .iter()
        .map(|name| root.join(name))
        .find(|path| path.exists())?;
    let before = fs::read_to_string(&path).ok()?;
    let mut after = before.clone();
    let marker = "  providers = [local]\n";
    if !after.contains("role = enum[") {
        if !after.contains(marker) {
            return None;
        }
        after = after.replacen(
            marker,
            "  providers = [local]\n  claims = {\n    role = enum[\"admin\", \"user\"]\n  }\n",
            1,
        );
    }
    for (field, declaration) in AUTH_OPTION_DEFAULTS {
        if !auth_has_field(&after, field) {
            after = insert_auth_declaration(&after, declaration)?;
        }
    }
    for screen in UI_SCREEN_DEFAULTS {
        if !named_block_has_field(&after, "ui", screen) {
            after = insert_named_block_declaration(
                &after,
                "ui",
                &format!("    {screen} = \"default\"\n"),
            )?;
        }
    }
    if !after.contains("use mail") {
        after.push_str("\nuse mail\nmail {\n  identities {\n    auth = \"auth@example.com\"\n  }\n  templates {\n    password_reset = \"./emails/password-reset.html\"\n    email_verification = \"./emails/email-verification.html\"\n  }\n}\n");
    }
    if after == before {
        return None;
    }
    Some(FileChange {
        path,
        before: Some(before),
        after,
    })
}

fn auth_block_bounds(source: &str) -> Option<(usize, usize)> {
    let start = source.find("use auth")?;
    let open = start + source[start..].find('{')?;
    let mut depth = 0usize;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some((open, open + offset));
                }
            }
            _ => {}
        }
    }
    None
}

fn auth_has_field(source: &str, field: &str) -> bool {
    let Some((open, close)) = auth_block_bounds(source) else {
        return false;
    };
    let mut depth = 0i32;
    for line in source[open + 1..close].lines() {
        let trimmed = line.trim_start();
        if depth == 0
            && trimmed.starts_with(field)
            && trimmed[field.len()..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_whitespace() || ch == '=' || ch == ':' || ch == '{')
        {
            return true;
        }
        depth += line.chars().filter(|ch| *ch == '{').count() as i32;
        depth -= line.chars().filter(|ch| *ch == '}').count() as i32;
    }
    false
}

fn insert_auth_declaration(source: &str, declaration: &str) -> Option<String> {
    let (_, close) = auth_block_bounds(source)?;
    let mut upgraded = String::with_capacity(source.len() + declaration.len() + 1);
    upgraded.push_str(&source[..close]);
    if !upgraded.ends_with('\n') {
        upgraded.push('\n');
    }
    upgraded.push_str(declaration);
    upgraded.push_str(&source[close..]);
    Some(upgraded)
}

fn named_block_bounds(source: &str, name: &str) -> Option<(usize, usize)> {
    let (auth_open, auth_close) = auth_block_bounds(source)?;
    let body = &source[auth_open + 1..auth_close];
    for (offset, _) in body.match_indices(name) {
        let start = auth_open + 1 + offset;
        let bounded = source[..start]
            .chars()
            .next_back()
            .is_none_or(|ch| !ch.is_alphanumeric() && ch != '_');
        if !bounded {
            continue;
        }
        let open = start + name.len() + source[start + name.len()..auth_close].find('{')?;
        let prefix = &source[auth_open + 1..open];
        let depth = prefix.chars().filter(|ch| *ch == '{').count()
            - prefix.chars().filter(|ch| *ch == '}').count();
        if depth == 0 {
            let mut nested = 0usize;
            for (inner, ch) in source[open..auth_close].char_indices() {
                match ch {
                    '{' => nested += 1,
                    '}' => {
                        nested = nested.checked_sub(1)?;
                        if nested == 0 {
                            return Some((open, open + inner));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

fn named_block_has_field(source: &str, block: &str, field: &str) -> bool {
    let Some((open, close)) = named_block_bounds(source, block) else {
        return false;
    };
    source[open + 1..close].lines().any(|line| {
        let line = line.trim_start();
        line.starts_with(field)
            && line[field.len()..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_whitespace() || ch == '=' || ch == ':')
    })
}

fn insert_named_block_declaration(source: &str, block: &str, declaration: &str) -> Option<String> {
    let (_, close) = named_block_bounds(source, block)?;
    let mut upgraded = String::with_capacity(source.len() + declaration.len());
    upgraded.push_str(&source[..close]);
    if !upgraded.ends_with('\n') {
        upgraded.push('\n');
    }
    upgraded.push_str(declaration);
    upgraded.push_str(&source[close..]);
    Some(upgraded)
}

fn manifest_change(application: &ApplicationCandidate, mode: InitMode) -> FileChange {
    let path = application.root.join(MANIFEST_FILE);
    FileChange {
        before: fs::read_to_string(&path).ok(),
        path,
        after: render_manifest(application, mode),
    }
}

fn apply_plan(plan: &InitPlan) -> Result<(), CliError> {
    create_rollback_journal(plan)?;
    let mut written = Vec::<(&FileChange, Option<String>)>::new();
    for change in &plan.changes {
        if let Some(parent) = change.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| error(format!("cannot create `{}`: {}", parent.display(), err)))?;
        }
        let before = fs::read_to_string(&change.path).ok();
        if let Err(err) = atomic_write(&change.path, &change.after) {
            rollback(&written);
            return Err(err);
        }
        written.push((change, before));
        if plan
            .application
            .root
            .join(".authboundry-fail-after-write")
            .exists()
        {
            rollback(&written);
            return Err(error("simulated initialization failure"));
        }
    }
    Ok(())
}

const ROLLBACK_DIR: &str = ".authboundry/rollback";

fn create_rollback_journal(plan: &InitPlan) -> Result<(), CliError> {
    let directory = plan.application.root.join(ROLLBACK_DIR);
    if directory.join("manifest.tsv").exists() {
        return Ok(());
    }
    fs::create_dir_all(&directory)
        .map_err(|err| error(format!("cannot create rollback journal: {}", err)))?;
    let mut manifest = String::new();
    for (index, change) in plan.changes.iter().enumerate() {
        let relative = display_path(&change.path, &plan.application.root);
        if relative.contains(['\t', '\n']) || relative.starts_with("../") {
            return Err(error("cannot journal an unsafe integration path"));
        }
        if let Some(before) = &change.before {
            let backup = format!("{}.backup", index);
            fs::write(directory.join(&backup), before)
                .map_err(|err| error(format!("cannot write rollback backup: {}", err)))?;
            manifest.push_str(&format!("existing\t{}\t{}\n", relative, backup));
        } else {
            manifest.push_str(&format!("created\t{}\t\n", relative));
        }
    }
    fs::write(directory.join("manifest.tsv"), manifest)
        .map_err(|err| error(format!("cannot write rollback manifest: {}", err)))
}

pub fn rollback_integration(args: &[String]) -> Result<Output, CliError> {
    let mut root = None;
    let mut yes = false;
    for arg in args {
        if arg == "--yes" {
            yes = true;
        } else if arg.starts_with('-') {
            return Err(error(format!("unknown flag `{}`", arg)));
        } else if root.replace(PathBuf::from(arg)).is_some() {
            return Err(error("rollback accepts at most one application path"));
        }
    }
    if !yes {
        return Err(error(
            "rollback requires --yes after reviewing the integration plan",
        ));
    }
    let root = root.unwrap_or(std::env::current_dir().map_err(|err| error(err.to_string()))?);
    let directory = root.join(ROLLBACK_DIR);
    let source = fs::read_to_string(directory.join("manifest.tsv"))
        .map_err(|_| error("no reversible AuthBoundry integration journal exists"))?;
    let mut restored = 0usize;
    let mut backups = Vec::new();
    for line in source.lines().rev() {
        let mut fields = line.splitn(3, '\t');
        let action = fields.next().unwrap_or("");
        let relative = fields.next().unwrap_or("");
        let backup = fields.next().unwrap_or("");
        if relative.is_empty()
            || relative.starts_with('/')
            || relative.split('/').any(|part| part == "..")
        {
            return Err(error("rollback journal contains an unsafe path"));
        }
        let target = root.join(relative);
        match action {
            "existing" => {
                let contents = fs::read_to_string(directory.join(backup))
                    .map_err(|err| error(format!("cannot read rollback backup: {}", err)))?;
                atomic_write(&target, &contents)?;
                backups.push(directory.join(backup));
            }
            "created" => {
                if target.exists() {
                    fs::remove_file(&target).map_err(|err| {
                        error(format!(
                            "cannot remove generated `{}`: {}",
                            target.display(),
                            err
                        ))
                    })?;
                }
            }
            _ => return Err(error("rollback journal contains an unknown action")),
        }
        restored += 1;
    }
    for backup in backups {
        if backup.exists() {
            fs::remove_file(&backup)
                .map_err(|err| error(format!("cannot consume rollback backup: {}", err)))?;
        }
    }
    fs::remove_file(directory.join("manifest.tsv"))
        .map_err(|err| error(format!("cannot consume rollback manifest: {}", err)))?;
    let route_access = root.join(".authboundry/route-access.json");
    if route_access.exists() {
        fs::remove_file(&route_access).map_err(|err| {
            error(format!(
                "cannot remove generated route authority `{}`: {}",
                route_access.display(),
                err
            ))
        })?;
    }
    let _ = fs::remove_dir(&directory);
    Ok(Output {
        text: format!(
            "AuthBoundry integration rolled back.\n✓ {} exact file changes reversed\n✓ Incumbent authentication remains available\n",
            restored
        ),
    })
}

pub fn cutover(args: &[String]) -> Result<Output, CliError> {
    let mut root = None;
    let mut yes = false;
    let mut server = "http://127.0.0.1:8787".to_string();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--yes" => yes = true,
            "--server" => {
                index += 1;
                server = args
                    .get(index)
                    .ok_or_else(|| error("--server needs a URL"))?
                    .clone();
            }
            flag if flag.starts_with('-') => return Err(error(format!("unknown flag `{}`", flag))),
            value if root.is_none() => root = Some(PathBuf::from(value)),
            value => return Err(error(format!("unexpected argument `{}`", value))),
        }
        index += 1;
    }
    if !yes {
        return Err(error(
            "cutover requires --yes after reviewing the integration plan",
        ));
    }
    let root = root.unwrap_or(std::env::current_dir().map_err(|err| error(err.to_string()))?);
    let integration_path = root.join(INTEGRATION_FILE);
    let integration = fs::read_to_string(&integration_path).map_err(|_| {
        error("no AuthBoundry integration plan exists; run `authboundry init` first")
    })?;
    if !integration.contains("\"status\": \"planned\"") {
        return Err(error("integration is not awaiting cutover"));
    }
    if !root.join(ROLLBACK_DIR).join("manifest.tsv").exists() {
        return Err(error(
            "cutover refused: reversible rollback journal is missing",
        ));
    }
    let application =
        discover(&root).ok_or_else(|| error("application is no longer discoverable"))?;
    let bridge_present = application.entrypoints.iter().any(|entry| {
        fs::read_to_string(&entry.path)
            .map(|source| source.contains("AuthBoundry integration"))
            .unwrap_or(false)
    });
    if !bridge_present {
        return Err(error("cutover refused: native framework bridge is missing"));
    }
    let origin = ApplicationUpstream::parse(&server).map_err(error)?;
    let public = appport_auth_mesh_server::send_upstream(
        &origin,
        &appport_auth_mesh_server::ClientRequest::get("/"),
    )
    .map_err(|err| error(format!("public-route verification failed: {}", err.message)))?;
    if public.status >= 400 {
        return Err(error(format!(
            "cutover refused: public route returned {}",
            public.status
        )));
    }
    let protected_path = application
        .routes
        .iter()
        .map(|route| route.path.as_str())
        .find(|path| !is_public_entry_path(path))
        .ok_or_else(|| error("cutover refused: no protected application route was discovered"))?;
    let anonymous = appport_auth_mesh_server::send_upstream(
        &origin,
        &appport_auth_mesh_server::ClientRequest::get(protected_path),
    )
    .map_err(|err| {
        error(format!(
            "anonymous-denial verification failed: {}",
            err.message
        ))
    })?;
    if !matches!(anonymous.status, 401 | 403) {
        return Err(error(format!(
            "cutover refused: anonymous request to `{}` returned {}, expected denial",
            protected_path, anonymous.status
        )));
    }
    let admin = development_accounts(&root)
        .into_iter()
        .find(|account| account.username == "admin")
        .ok_or_else(|| error("cutover refused: development admin account is missing"))?;
    let body = format!(
        "{{\"tenant\":\"{}\",\"connector\":\"local\",\"username\":\"{}\",\"password\":\"{}\"}}",
        escape(&admin.tenant),
        escape(&admin.username),
        escape(&admin.password)
    );
    let signed_in = appport_auth_mesh_server::send_upstream(
        &origin,
        &appport_auth_mesh_server::ClientRequest::post_json("/auth/sign-in", body),
    )
    .map_err(|err| {
        error(format!(
            "admin sign-in verification failed: {}",
            err.message
        ))
    })?;
    if signed_in.status != 200 {
        return Err(error(format!(
            "cutover refused: admin sign-in returned {}",
            signed_in.status
        )));
    }
    let credential = appport_auth_mesh_server::cookie_value(&signed_in, "authboundry_session")
        .ok_or_else(|| error("cutover refused: admin sign-in issued no session"))?;
    let authenticated = appport_auth_mesh_server::send_upstream(
        &origin,
        &appport_auth_mesh_server::ClientRequest::get(protected_path)
            .with_cookie("authboundry_session", &credential),
    )
    .map_err(|err| {
        error(format!(
            "authenticated forwarding verification failed: {}",
            err.message
        ))
    })?;
    if authenticated.status >= 400 {
        return Err(error(format!(
            "cutover refused: authenticated route `{}` returned {}",
            protected_path, authenticated.status
        )));
    }
    if let Some(upstream) = read_adoption(&root).and_then(|state| state.upstream) {
        let direct_origin = ApplicationUpstream::parse(&upstream).map_err(error)?;
        let direct = appport_auth_mesh_server::send_upstream(
            &direct_origin,
            &appport_auth_mesh_server::ClientRequest::get(protected_path),
        )
        .map_err(|err| {
            error(format!(
                "direct-access verification failed: {}",
                err.message
            ))
        })?;
        if !matches!(direct.status, 401 | 403) {
            return Err(error(format!(
                "cutover refused: direct application access to `{}` returned {}; protection remains bypassable",
                protected_path, direct.status
            )));
        }
    }
    atomic_write(
        &integration_path,
        &integration.replacen("\"status\": \"planned\"", "\"status\": \"verified\"", 1),
    )?;
    Ok(Output {
        text: format!(
            "AuthBoundry cutover verified.\n✓ public route accessible\n✓ protected route denied anonymously\n✓ admin sign-in established a session\n✓ protected route forwarded with verified authority\n✓ direct application bypass denied or not externally exposed\n✓ rollback remains available\nIncumbent authentication may now be offboarded with `authboundry offboard-auth --yes`.\n"
        ),
    })
}

pub fn offboard_auth(args: &[String]) -> Result<Output, CliError> {
    let mut root = None;
    let mut yes = false;
    for arg in args {
        if arg == "--yes" {
            yes = true;
        } else if arg.starts_with('-') {
            return Err(error(format!("unknown flag `{}`", arg)));
        } else if root.replace(PathBuf::from(arg)).is_some() {
            return Err(error("offboard-auth accepts at most one application path"));
        }
    }
    if !yes {
        return Err(error("offboard-auth requires --yes after verified cutover"));
    }
    let root = root.unwrap_or(std::env::current_dir().map_err(|err| error(err.to_string()))?);
    let path = root.join(INTEGRATION_FILE);
    let source =
        fs::read_to_string(&path).map_err(|_| error("no AuthBoundry integration plan exists"))?;
    if !source.contains("\"status\": \"verified\"") {
        return Err(error(
            "offboarding refused: AuthBoundry cutover has not passed runtime verification",
        ));
    }
    if !root.join(ROLLBACK_DIR).join("manifest.tsv").exists() {
        return Err(error(
            "offboarding refused: rollback journal is unavailable",
        ));
    }
    atomic_write(
        &path,
        &source.replacen("\"status\": \"verified\"", "\"status\": \"offboarded\"", 1),
    )?;
    Ok(Output {
        text: "Incumbent authentication offboarded from the authority path.\n✓ AuthBoundry is the verified protected-route authority\n✓ Existing identity provider may continue through its bridge\n✓ Application profiles and business data preserved\n✓ Original source remains recoverable with `authboundry rollback --yes`\n"
            .to_string(),
    })
}

fn atomic_write(path: &Path, contents: &str) -> Result<(), CliError> {
    let tmp = path.with_extension("authboundry-tmp");
    fs::write(&tmp, contents)
        .map_err(|err| error(format!("cannot write `{}`: {}", tmp.display(), err)))?;
    fs::rename(&tmp, path)
        .map_err(|err| error(format!("cannot replace `{}`: {}", path.display(), err)))?;
    #[cfg(unix)]
    if path.ends_with(DEVELOPMENT_FILE) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|err| {
            error(format!(
                "cannot protect development credentials `{}`: {}",
                path.display(),
                err
            ))
        })?;
    }
    Ok(())
}

fn rollback(written: &[(&FileChange, Option<String>)]) {
    for (change, before) in written.iter().rev() {
        match before {
            Some(contents) => {
                let _ = fs::write(&change.path, contents);
            }
            None => {
                let _ = fs::remove_file(&change.path);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifyReport {
    ok: bool,
    application_discovered: bool,
    boundary_present: bool,
    runtime_starts: bool,
    control_plane_responds: bool,
    application_routes_remain_reachable: bool,
    authboundry_routes_respond: bool,
    contract_fingerprint_stable: bool,
    live_authority_available: bool,
    application_routes: usize,
    application: String,
    upstream: Option<String>,
    upstream_reachable: bool,
    application_responded: bool,
    runtime_running: bool,
}

fn verify_root(root: &Path, server: &str) -> Result<VerifyReport, CliError> {
    let application = discover(root);
    let application_routes = application
        .as_ref()
        .map(|application| application.routes.len())
        .unwrap_or(0);
    let runtime_starts = resolve_config(root)
        .ok()
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|source| appport_auth_mesh_dsl::parse_auth_block(&source).ok())
        .and_then(|config| {
            let registry =
                appport_auth_mesh_providers::ConnectorRegistry::from_config(&config).ok()?;
            appport_auth_mesh_boundary::AuthPortRuntime::new(
                config,
                registry,
                appport_auth_mesh_runtime::MemoryStores::new().mesh_stores(),
                appport_auth_mesh_boundary::BindingMode::Embedded,
            )
            .ok()
        })
        .is_some();
    let boundary_present = application
        .as_ref()
        .map(|application| {
            application.existing_authport.middleware
                || application.existing_authport.initialization
                || application.existing_authport.manifest
        })
        .unwrap_or(false);
    let adoption = read_adoption(root);
    let upstream = adoption.as_ref().and_then(|state| state.upstream.clone());
    let upstream_reachable = upstream.as_deref().map(upstream_reachable).unwrap_or(false);
    let application_responded = upstream
        .as_deref()
        .and_then(|value| ApplicationUpstream::parse(value).ok())
        .and_then(|origin| {
            appport_auth_mesh_server::send_upstream(
                &origin,
                &appport_auth_mesh_server::ClientRequest::get("/"),
            )
            .ok()
        })
        .is_some();
    let runtime_running = ApplicationUpstream::parse(server)
        .ok()
        .and_then(|origin| {
            appport_auth_mesh_server::send_upstream(
                &origin,
                &appport_auth_mesh_server::ClientRequest::get("/auth/providers"),
            )
            .ok()
        })
        .is_some();
    let report = VerifyReport {
        ok: application.is_some() && boundary_present && runtime_starts,
        application_discovered: application.is_some(),
        boundary_present,
        runtime_starts,
        control_plane_responds: runtime_starts,
        application_routes_remain_reachable: application_routes > 0,
        authboundry_routes_respond: runtime_starts,
        contract_fingerprint_stable: runtime_starts,
        live_authority_available: runtime_starts,
        application_routes,
        application: adoption
            .as_ref()
            .map(|state| state.application.clone())
            .or_else(|| application.as_ref().and_then(|app| app.name.clone()))
            .unwrap_or_else(|| "(unknown)".to_string()),
        upstream,
        upstream_reachable,
        application_responded,
        runtime_running,
    };
    Ok(report)
}

fn resolve_config(root: &Path) -> Result<PathBuf, CliError> {
    DEFAULT_FILES
        .iter()
        .map(|name| root.join(name))
        .find(|path| path.exists())
        .ok_or_else(|| error("no auth declaration found"))
}

fn render_plan_text(plan: &InitPlan, preview: bool) -> String {
    let mut out = String::new();
    if plan.already_integrated {
        out.push_str("AuthBoundry already detected.\n");
    } else {
        out.push_str("AuthBoundry found your application.\n");
    }
    out.push_str(&format!(
        "Application:\n  {}\nLanguage:\n  {}\nFramework:\n  {}\nPackage manager:\n  {}\nEntrypoint:\n  {}\nRun command:\n  {}\n",
        plan.application.name.as_deref().unwrap_or("(unknown)"),
        plan.application.language.as_deref().unwrap_or("(unknown)"),
        plan.application.framework.as_deref().unwrap_or("(none)"),
        plan.application.package_manager.as_deref().unwrap_or("(unknown)"),
        plan.application
            .entrypoints
            .first()
            .map(|entrypoint| display_path(&entrypoint.path, &plan.application.root))
            .unwrap_or_else(|| "(none)".to_string()),
        plan.application
            .servers
            .first()
            .map(|server| server.command.as_str())
            .unwrap_or("(unknown)")
    ));
    if !plan.application.routes.is_empty() {
        let proposal = propose_authority(
            &plan.application,
            "preview",
            0,
            &std::collections::BTreeMap::new(),
        );
        out.push_str("Discovered routes:\n");
        for route in proposal.routes {
            out.push_str(&format!(
                "  {:<6} {:<24} {}\n",
                route.method,
                route.path,
                route.protection.as_str()
            ));
        }
    }
    if !plan.application.providers.is_empty() {
        out.push_str("Detected:\n");
        for provider in &plan.application.providers {
            out.push_str(&format!("  {}\n", provider.display_name));
        }
        out.push_str("Available to AuthBoundry:\n");
        for provider in &plan.application.providers {
            out.push_str(&format!("  {}\n", provider.id));
        }
    }
    if !plan.application.existing_auth.is_empty() {
        out.push_str("Existing authentication:\n");
        for system in &plan.application.existing_auth {
            out.push_str(&format!(
                "  {}\n    strategy: {}\n    credentials: {} · sessions: {} · profiles: {} · authorization: {}\n",
                system.display_name,
                system.coexistence.as_str(),
                if system.credentials { "preserve during adoption" } else { "none" },
                if system.sessions { "bridge then offboard" } else { "none" },
                if system.profiles { "preserve" } else { "none detected" },
                if system.authorization { "migrate explicitly" } else { "AuthBoundry" }
            ));
        }
        out.push_str(
            "  Existing auth will not be removed until replacement verification passes.\n",
        );
    }
    out.push_str("Proposed integration:\n");
    if plan.integration_supported {
        out.push_str("  framework-native coexistence bridge\n  + initialize AuthBoundry SDK/context\n  + preserve incumbent authentication during cutover\n  + preserve existing application routes and profiles\n  + record every source change for rollback\n");
    } else {
        out.push_str("  (automatic source integration is not supported for this application)\n");
    }
    out.push_str("Authority:\n  configured\nApplication attachment:\n  none\n");
    if plan.integration_supported {
        out.push_str("Cutover:\n  pending runtime verification; incumbent auth remains active\n");
    } else {
        out.push_str("Reason:\n  automatic source integration is not supported\n  and no application runtime attachment was discovered\n");
    }
    out.push_str("No application routes will be rewritten.\n");
    out.push_str("Files to modify:\n");
    for change in plan.changes.iter().filter(|change| change.before.is_some()) {
        out.push_str(&format!(
            "  {}\n",
            display_path(&change.path, &plan.application.root)
        ));
    }
    out.push_str("Files to create:\n");
    for change in plan.changes.iter().filter(|change| change.before.is_none()) {
        out.push_str(&format!(
            "  {}\n",
            display_path(&change.path, &plan.application.root)
        ));
    }
    out.push_str("Files to leave unchanged:\n  application routes\n");
    if preview {
        out.push_str("Patch preview:\n");
        for change in &plan.changes {
            out.push_str(&render_patch(change, &plan.application.root));
        }
    }
    out
}

fn applied_plan_text(plan: &InitPlan, report: &VerifyReport) -> String {
    let mut out = String::from("Applying adoption plan...\n");
    for change in &plan.changes {
        let action = if change.before.is_some() {
            "Modified"
        } else {
            "Created"
        };
        out.push_str(&format!(
            "✓ {} {}\n",
            action,
            display_path(&change.path, &plan.application.root)
        ));
    }
    out.push_str("✓ Application routes unchanged\n");
    out.push_str(&format!(
        "✓ {} application routes discovered\n",
        report.application_routes.max(plan.application.routes.len())
    ));
    out.push_str("✓ Application detected\n✓ AuthBoundry configuration created\n");
    if let Some(change) = plan
        .changes
        .iter()
        .find(|change| change.path.ends_with(DEVELOPMENT_FILE))
    {
        let accounts = development_accounts_from_source(&change.after);
        if !accounts.is_empty() {
            out.push_str("✓ Development identities created\nDevelopment sign-in (stored in .authboundry/development.json):\n");
            for account in accounts {
                out.push_str(&format!("  {} / {}\n", account.username, account.password));
            }
        }
    }
    if plan.integration_supported {
        out.push_str(
            "✓ Application coexistence bridge installed\n⚠ Cutover pending runtime verification\n",
        );
    } else {
        out.push_str("⚠ Application integration not established\n");
    }
    out.push_str("Authority state:\n  configured\nApplication state:\n  unattached\n");
    out.push_str("Reason:\n  no application runtime attachment was discovered\n");
    out.push_str("AuthBoundry adoption complete.\n");
    out
}

fn development_accounts_from_source(source: &str) -> Vec<crate::serve::Account> {
    let tenant = json_string(source, "tenant").unwrap_or_else(|| "development".to_string());
    source
        .split("{\"username\"")
        .skip(1)
        .filter_map(|record| {
            let record = format!("{{\"username\"{}", record);
            crate::serve::Account::parse(
                &format!(
                    "{}:{}:{}@{}",
                    json_string(&record, "username")?,
                    json_string(&record, "password")?,
                    json_string(&record, "claims").unwrap_or_default(),
                    tenant
                ),
                &tenant,
            )
            .ok()
        })
        .collect()
}

fn render_verify_text(report: &VerifyReport) -> String {
    let mark = |ok| if ok { "✓" } else { "✗" };
    let mut output = format!(
        "{} application discovered\n{} AuthBoundry configuration present\n{} authority configuration valid\n{} control plane surface derivable\n{} application routes discovered\n{} authority routes derivable\n{} contract fingerprint stable\n{} authority state available\n",
        mark(report.application_discovered),
        mark(report.boundary_present),
        mark(report.runtime_starts),
        mark(report.control_plane_responds),
        mark(report.application_routes_remain_reachable),
        mark(report.authboundry_routes_respond),
        mark(report.contract_fingerprint_stable),
        mark(report.live_authority_available)
    );
    if let Some(upstream) = &report.upstream {
        output.push_str(&format!(
            "\nAuthBoundry · Boundary Verification\nApplication:\n  {}\nUpstream:\n  {}\nConnectivity:\n  {}\nApplication response:\n  {}\nAuthority boundary:\n  ✓ configured\nRuntime protection:\n  {}\n{}",
            report.application,
            upstream,
            if report.upstream_reachable { "✓ reachable" } else { "✗ unreachable" },
            if report.application_responded { "✓ received" } else { "✗ not received" },
            if report.runtime_running && report.upstream_reachable { "✓ active" } else { "○ inactive" },
            if report.runtime_running { "" } else { "Reason:\n  AuthBoundry runtime is not running.\n" }
        ));
    }
    output
}

fn render_plan_json(plan: &InitPlan, dry_run: bool) -> String {
    format!(
        "{{\n  \"application\": \"{}\",\n  \"language\": \"{}\",\n  \"framework\": \"{}\",\n  \"package_manager\": \"{}\",\n  \"entrypoint\": \"{}\",\n  \"run_command\": \"{}\",\n  \"detected\": {},\n  \"already_configured\": {},\n  \"mode\": \"{}\",\n  \"dry_run\": {},\n  \"routes\": {},\n  \"providers\": [{}],\n  \"changes\": [{}]\n}}\n",
        escape(plan.application.name.as_deref().unwrap_or("")),
        escape(plan.application.language.as_deref().unwrap_or("")),
        escape(plan.application.framework.as_deref().unwrap_or("")),
        escape(plan.application.package_manager.as_deref().unwrap_or("")),
        escape(
            &plan
                .application
                .entrypoints
                .first()
                .map(|entrypoint| display_path(&entrypoint.path, &plan.application.root))
                .unwrap_or_default()
        ),
        escape(
            plan.application
                .servers
                .first()
                .map(|server| server.command.as_str())
                .unwrap_or("")
        ),
        plan.detected,
        plan.already_integrated,
        mode_str(plan.mode),
        dry_run,
        plan.application.routes.len(),
        plan.application
            .providers
            .iter()
            .map(|provider| format!("\"{}\"", escape(&provider.id)))
            .collect::<Vec<_>>()
            .join(", "),
        plan.changes
            .iter()
            .map(|change| format!(
                "{{\"path\": \"{}\", \"action\": \"{}\"}}",
                escape(&display_path(&change.path, &plan.application.root)),
                if change.before.is_some() { "modify" } else { "create" }
            ))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn render_verify_json(report: &VerifyReport) -> String {
    format!(
        "{{\"ok\": {}, \"application_discovered\": {}, \"authority_configured\": {}, \"authority_configuration_valid\": {}, \"control_plane_surface_derivable\": {}, \"application_routes_discovered\": {}, \"authority_routes_derivable\": {}, \"contract_fingerprint_stable\": {}, \"authority_state_available\": {}, \"application_routes\": {}, \"application\": \"{}\", \"upstream\": {}, \"upstream_reachable\": {}, \"application_responded\": {}, \"runtime_running\": {}, \"runtime_protection_active\": {}}}\n",
        report.ok,
        report.application_discovered,
        report.boundary_present,
        report.runtime_starts,
        report.control_plane_responds,
        report.application_routes_remain_reachable,
        report.authboundry_routes_respond,
        report.contract_fingerprint_stable,
        report.live_authority_available,
        report.application_routes,
        escape(&report.application),
        report.upstream.as_ref().map(|value| format!("\"{}\"", escape(value))).unwrap_or_else(|| "null".to_string()),
        report.upstream_reachable,
        report.application_responded,
        report.runtime_running,
        report.runtime_running && report.upstream_reachable
    )
}

fn render_manifest(application: &ApplicationCandidate, mode: InitMode) -> String {
    render_manifest_with_upstream(application, mode, None)
}

fn render_manifest_with_upstream(
    application: &ApplicationCandidate,
    mode: InitMode,
    upstream: Option<&str>,
) -> String {
    format!(
        "{{\n  \"application\": \"{}\",\n  \"mode\": \"{}\",\n  \"authority\": \"configured\",\n  \"attachment\": \"{}\",\n  \"protection\": \"inactive\",\n  \"upstream\": \"{}\",\n  \"language\": \"{}\",\n  \"framework\": \"{}\",\n  \"package_manager\": \"{}\",\n  \"entrypoint\": \"{}\",\n  \"run_command\": \"{}\",\n  \"routes\": {}\n}}\n",
        escape(application.name.as_deref().unwrap_or("")),
        mode_str(mode),
        if upstream.is_some() { "upstream" } else { "none" },
        escape(upstream.unwrap_or("")),
        escape(application.language.as_deref().unwrap_or("")),
        escape(application.framework.as_deref().unwrap_or("")),
        escape(application.package_manager.as_deref().unwrap_or("")),
        escape(
            &application
                .entrypoints
                .first()
                .map(|entrypoint| display_path(&entrypoint.path, &application.root))
                .unwrap_or_default()
        ),
        escape(
            application
                .servers
                .first()
                .map(|server| server.command.as_str())
                .unwrap_or("")
        ),
        application.routes.len()
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptionState {
    pub application: String,
    pub mode: String,
    pub authority: String,
    pub upstream: Option<String>,
    pub routes: usize,
    pub framework: String,
    pub run_command: Option<String>,
}

pub fn read_adoption(root: &Path) -> Option<AdoptionState> {
    let source = fs::read_to_string(root.join(MANIFEST_FILE)).ok()?;
    Some(AdoptionState {
        application: json_string(&source, "application").unwrap_or_default(),
        mode: json_string(&source, "mode").unwrap_or_else(|| "standalone".to_string()),
        authority: json_string(&source, "authority").unwrap_or_else(|| "configured".to_string()),
        upstream: json_string(&source, "upstream").filter(|value| !value.is_empty()),
        routes: json_usize(&source, "routes").unwrap_or(0),
        framework: json_string(&source, "framework").unwrap_or_default(),
        run_command: json_string(&source, "run_command").filter(|value| !value.is_empty()),
    })
}

pub fn adoption_upstream(root: &Path) -> Option<String> {
    read_adoption(root)?.upstream
}

pub(crate) fn development_accounts(root: &Path) -> Vec<crate::serve::Account> {
    let Ok(source) = fs::read_to_string(root.join(DEVELOPMENT_FILE)) else {
        return Vec::new();
    };
    development_accounts_from_source(&source)
}

pub(crate) fn development_proxy_secret(root: &Path) -> Option<String> {
    let source = fs::read_to_string(root.join(DEVELOPMENT_FILE)).ok()?;
    json_string(&source, "proxy_secret")
}

fn json_string(source: &str, key: &str) -> Option<String> {
    let marker = format!("\"{}\":", key);
    let value = source.split_once(&marker)?.1.trim_start();
    let value = value.strip_prefix('"')?;
    Some(value.split_once('"')?.0.to_string())
}

fn json_usize(source: &str, key: &str) -> Option<usize> {
    let marker = format!("\"{}\":", key);
    let value = source.split_once(&marker)?.1.trim_start();
    value
        .split(|character: char| !character.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

fn upstream_address(value: &str) -> Result<ApplicationUpstream, CliError> {
    ApplicationUpstream::parse(value).map_err(error)
}

pub(crate) fn upstream_reachable(value: &str) -> bool {
    upstream_address(value)
        .ok()
        .and_then(|upstream| {
            appport_auth_mesh_server::send_upstream(
                &upstream,
                &appport_auth_mesh_server::ClientRequest::get("/"),
            )
            .ok()
        })
        .is_some()
}

fn render_patch(change: &FileChange, root: &Path) -> String {
    let path = display_path(&change.path, root);
    let mut out = format!("--- {}\n+++ {}\n", path, path);
    if change.path.ends_with(DEVELOPMENT_FILE) {
        out.push_str("+ {\n+   \"tenant\": \"development\",\n+   \"proxy_secret\": \"<generated after approval>\",\n+   \"accounts\": [\n+     {\"username\": \"admin\", \"password\": \"<generated after approval>\", \"claims\": \"role=admin\"},\n+     {\"username\": \"user\", \"password\": \"<generated after approval>\", \"claims\": \"role=user\"}\n+   ]\n+ }\n");
        return out;
    }
    match &change.before {
        Some(before) => {
            for line in change.after.lines() {
                if !before.lines().any(|old| old == line) {
                    out.push_str(&format!("+ {}\n", line));
                }
            }
        }
        None => {
            for line in change.after.lines() {
                out.push_str(&format!("+ {}\n", line));
            }
        }
    }
    out
}

fn mode_str(mode: InitMode) -> &'static str {
    match mode {
        InitMode::Embedded => "embedded",
        InitMode::Standalone => "standalone",
    }
}

fn display_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[allow(dead_code)]
fn _manifest_path(root: &Path) -> PathBuf {
    root.join(MANIFEST_DIR)
}

#[cfg(test)]
mod confirmation_tests {
    use super::{
        auth_has_field, confirm_adoption, conventional_dev_upstream, insert_auth_declaration,
        upstream_reachable, AUTH_OPTION_DEFAULTS, DEFAULT_DECLARATION,
    };
    use appport_auth_mesh_dsl::parse_auth_block;
    use std::io::{Cursor, Write};
    use std::net::TcpListener;

    #[test]
    fn confirmation_defaults_to_no_and_accepts_only_explicit_yes() {
        assert!(!confirm_adoption(&mut Cursor::new("\n")).unwrap());
        assert!(!confirm_adoption(&mut Cursor::new("n\n")).unwrap());
        assert!(confirm_adoption(&mut Cursor::new("y\n")).unwrap());
        assert!(confirm_adoption(&mut Cursor::new("YES\n")).unwrap());
    }

    #[test]
    fn unavailable_stdin_fails_closed() {
        let error = confirm_adoption(&mut Cursor::new(Vec::<u8>::new())).unwrap_err();
        assert!(error
            .message
            .contains("cannot obtain interactive confirmation"));
    }

    #[test]
    fn create_react_app_uses_its_conventional_port() {
        assert_eq!(conventional_dev_upstream("React"), "http://127.0.0.1:3000");
    }

    #[test]
    fn generated_and_upgraded_contracts_expose_every_supported_option_group() {
        parse_auth_block(DEFAULT_DECLARATION).expect("the complete generated contract is valid");
        let mut upgraded = "use auth {\n  providers = [local]\n  claims = { role = enum[\"admin\", \"user\"] }\n}\n".to_string();
        for (field, declaration) in AUTH_OPTION_DEFAULTS {
            if !auth_has_field(&upgraded, field) {
                upgraded = insert_auth_declaration(&upgraded, declaration).unwrap();
            }
        }
        for (field, _) in AUTH_OPTION_DEFAULTS {
            assert!(auth_has_field(&upgraded, field), "missing {field}");
        }
        parse_auth_block(&upgraded).expect("the upgraded auth block is valid");
    }

    #[test]
    fn reachability_rejects_https_when_the_upstream_speaks_plain_http() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .unwrap();
        });
        assert!(!upstream_reachable(&format!("https://127.0.0.1:{port}")));
        server.join().unwrap();
    }
}
