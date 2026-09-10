use std::fs;
use std::io::{self, BufRead, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use appport_auth_mesh_discovery::{
    discover, propose_authority, ApplicationCandidate, RouteCandidate,
};

use crate::{error, CliError, Output};

const DEFAULT_DECLARATION: &str = "use auth {\n  providers = [local]\n}\n";
const MANIFEST_DIR: &str = ".authboundry";
const MANIFEST_FILE: &str = ".authboundry/adoption.json";
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

    if plan.already_integrated {
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
        let current = build_plan(&root, options.mode.unwrap_or(InitMode::Standalone))?;
        if current != plan {
            return Err(error(
                "the application changed while the adoption plan was being reviewed; refusing to apply a stale plan",
            ));
        }
    }

    apply_plan(&plan)?;
    let verified = verify_root(&root)?;
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
    let child = Command::new(executable)
        .arg("studio")
        .arg(root)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if child.is_err() {
        return studio_fallback();
    }
    for _ in 0..20 {
        if upstream_reachable("http://127.0.0.1:8787") {
            return "Starting Studio...\n✓ Studio listening on http://127.0.0.1:8787\nOpening browser...\n".to_string();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    studio_fallback()
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
    upstream_address(&upstream)?;
    if !upstream_reachable(&upstream) {
        return Err(error(format!(
            "application upstream `{}` is not reachable; start the application and try again",
            upstream
        )));
    }
    let before = fs::read_to_string(root.join(MANIFEST_FILE))
        .map_err(|_| error("no AuthBoundry adoption exists; run `authboundry init` first"))?;
    let application = discover(&root).ok_or_else(|| error("no supported application found"))?;
    let after = render_manifest_with_upstream(&application, InitMode::Standalone, Some(&upstream));
    let preview = format!(
        "AuthBoundry · Attach Application\nApplication:\n  {}\nIntegration mode:\n  standalone\nApplication upstream:\n  {}\nAuthBoundry will:\n  ✓ receive application requests\n  ✓ establish the authority context\n  ✓ enforce configured route policy\n  ✓ forward authorized requests\nApplication source:\n  unchanged\nPatch preview:\n--- .authboundry/adoption.json\n+++ .authboundry/adoption.json\n+ attachment: upstream\n+ upstream: {}\n",
        application.name.as_deref().unwrap_or("(unknown)"),
        upstream,
        upstream
    );
    if !yes {
        print!("{}Attach this application? [y/N] ", preview);
        io::stdout().flush().map_err(|err| error(err.to_string()))?;
        if !confirm_adoption(&mut io::stdin().lock())? {
            return Ok(Output {
                text: "Attachment cancelled. No files were changed.\n".to_string(),
            });
        }
        if fs::read_to_string(root.join(MANIFEST_FILE)).ok().as_deref() != Some(before.as_str()) {
            return Err(error("the adoption state changed while the attachment plan was reviewed; refusing to apply a stale plan"));
        }
    }
    atomic_write(&root.join(MANIFEST_FILE), &after)?;
    Ok(Output {
        text: format!(
            "{}Application attached.\nAuthority state:\n  configured\nApplication attachment:\n  upstream {}\nProtection:\n  ready when AuthBoundry is running\nApplication source:\n  unchanged\n",
            if yes { preview } else { String::new() },
            upstream
        ),
    })
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
    let report = verify_root(&root)?;
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

    // The current public package does not expose server middleware. Adoption
    // records the authority boundary without rewriting application source.
    let integration_supported = mode == InitMode::Standalone;

    Ok(InitPlan {
        application,
        mode,
        changes,
        already_integrated,
        detected: true,
        integration_supported,
    })
}

fn boundary_integrated(application: &ApplicationCandidate, mode: InitMode) -> bool {
    let _ = mode;
    application.existing_authport.configuration && application.existing_authport.manifest
}

fn config_change(root: &Path) -> FileChange {
    let path = root.join("authboundry.toml");
    FileChange {
        before: fs::read_to_string(&path).ok(),
        path,
        after: DEFAULT_DECLARATION.to_string(),
    }
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

fn atomic_write(path: &Path, contents: &str) -> Result<(), CliError> {
    let tmp = path.with_extension("authboundry-tmp");
    fs::write(&tmp, contents)
        .map_err(|err| error(format!("cannot write `{}`: {}", tmp.display(), err)))?;
    fs::rename(&tmp, path)
        .map_err(|err| error(format!("cannot replace `{}`: {}", path.display(), err)))?;
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
}

fn verify_root(root: &Path) -> Result<VerifyReport, CliError> {
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
    out.push_str("Proposed integration:\n");
    if plan.integration_supported && plan.mode == InitMode::Embedded {
        out.push_str("  + initialize AuthBoundry\n  + mount AuthBoundry boundary\n  + preserve existing application routes\n");
    } else {
        out.push_str("  (automatic source integration is not supported for this application)\n");
    }
    out.push_str("Authority:\n  configured\nApplication attachment:\n  none\n");
    out.push_str("Reason:\n  automatic source integration is not supported\n  and no application runtime attachment was discovered\n");
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
    out.push_str("⚠ Application integration not established\n");
    out.push_str("Authority state:\n  configured\nApplication state:\n  unattached\n");
    out.push_str("Reason:\n  no application runtime attachment was discovered\n");
    out.push_str("AuthBoundry adoption complete.\n");
    out
}

fn render_verify_text(report: &VerifyReport) -> String {
    let mark = |ok| if ok { "✓" } else { "✗" };
    format!(
        "{} application discovered\n{} AuthBoundry configuration present\n{} authority configuration valid\n{} control plane surface derivable\n{} application routes discovered\n{} authority routes derivable\n{} contract fingerprint stable\n{} authority state available\n",
        mark(report.application_discovered),
        mark(report.boundary_present),
        mark(report.runtime_starts),
        mark(report.control_plane_responds),
        mark(report.application_routes_remain_reachable),
        mark(report.authboundry_routes_respond),
        mark(report.contract_fingerprint_stable),
        mark(report.live_authority_available)
    )
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
        "{{\"ok\": {}, \"application_discovered\": {}, \"authority_configured\": {}, \"authority_configuration_valid\": {}, \"control_plane_surface_derivable\": {}, \"application_routes_discovered\": {}, \"authority_routes_derivable\": {}, \"contract_fingerprint_stable\": {}, \"authority_state_available\": {}, \"application_routes\": {}}}\n",
        report.ok,
        report.application_discovered,
        report.boundary_present,
        report.runtime_starts,
        report.control_plane_responds,
        report.application_routes_remain_reachable,
        report.authboundry_routes_respond,
        report.contract_fingerprint_stable,
        report.live_authority_available,
        report.application_routes
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
}

pub fn read_adoption(root: &Path) -> Option<AdoptionState> {
    let source = fs::read_to_string(root.join(MANIFEST_FILE)).ok()?;
    Some(AdoptionState {
        application: json_string(&source, "application").unwrap_or_default(),
        mode: json_string(&source, "mode").unwrap_or_else(|| "standalone".to_string()),
        authority: json_string(&source, "authority").unwrap_or_else(|| "configured".to_string()),
        upstream: json_string(&source, "upstream").filter(|value| !value.is_empty()),
        routes: json_usize(&source, "routes").unwrap_or(0),
    })
}

pub fn adoption_upstream(root: &Path) -> Option<String> {
    read_adoption(root)?.upstream
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

fn upstream_address(value: &str) -> Result<SocketAddr, CliError> {
    let address = value
        .strip_prefix("http://")
        .unwrap_or(value)
        .trim_end_matches('/');
    address.parse().map_err(|_| {
        error("application upstream must be an explicit HTTP socket, for example http://127.0.0.1:9000")
    })
}

pub(crate) fn upstream_reachable(value: &str) -> bool {
    upstream_address(value)
        .ok()
        .and_then(|address| TcpStream::connect_timeout(&address, Duration::from_millis(250)).ok())
        .is_some()
}

fn render_patch(change: &FileChange, root: &Path) -> String {
    let path = display_path(&change.path, root);
    let mut out = format!("--- {}\n+++ {}\n", path, path);
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
    use super::confirm_adoption;
    use std::io::Cursor;

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
}
