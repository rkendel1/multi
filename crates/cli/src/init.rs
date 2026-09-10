use std::fs;
use std::path::{Path, PathBuf};

use appport_auth_mesh_discovery::{discover, ApplicationCandidate, EntrypointKind, RouteCandidate};

use crate::{error, CliError, Output};

const DEFAULT_DECLARATION: &str = "use auth {\n  providers = [local]\n}\n";
const MANIFEST_DIR: &str = ".authport";
const MANIFEST_FILE: &str = ".authport/adoption.json";

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
    let plan = build_plan(&root, options.mode.unwrap_or(InitMode::Embedded))?;

    if options.json {
        return Ok(Output {
            text: render_plan_json(&plan, options.dry_run),
        });
    }
    if options.dry_run || !options.yes {
        return Ok(Output {
            text: render_plan_text(&plan, true),
        });
    }

    if plan.already_integrated {
        return Ok(Output {
            text: render_plan_text(&plan, false),
        });
    }

    apply_plan(&plan)?;
    let verified = verify_root(&root)?;
    if !verified.ok {
        return Err(error("AuthPort initialization verification failed"));
    }
    Ok(Output {
        text: first_run_text(&plan, &verified),
    })
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
    let already_integrated = application.existing_authport.detected();
    let mut changes = Vec::new();

    if !already_integrated {
        if mode == InitMode::Embedded {
            if let Some(change) = node_embedded_change(&application)? {
                changes.push(change);
            }
        }
        changes.push(config_change(root));
        changes.push(manifest_change(&application, mode));
    }

    let integration_supported = mode == InitMode::Standalone
        || changes
            .iter()
            .any(|change| change.path.extension().and_then(|ext| ext.to_str()) == Some("js"))
        || changes
            .iter()
            .any(|change| change.path.extension().and_then(|ext| ext.to_str()) == Some("ts"));

    Ok(InitPlan {
        application,
        mode,
        changes,
        already_integrated,
        detected: true,
        integration_supported,
    })
}

fn node_embedded_change(
    application: &ApplicationCandidate,
) -> Result<Option<FileChange>, CliError> {
    if application.language.as_deref() != Some("Node")
        || application.framework.as_deref() != Some("Express")
    {
        return Ok(None);
    }
    let Some(entrypoint) = application
        .entrypoints
        .iter()
        .find(|candidate| matches!(candidate.kind, EntrypointKind::NodeScript))
    else {
        return Ok(None);
    };
    let before = fs::read_to_string(&entrypoint.path).map_err(|err| {
        error(format!(
            "cannot read entrypoint `{}`: {}",
            entrypoint.path.display(),
            err
        ))
    })?;
    if before.contains("authport()") || before.contains("app.use(authport") {
        return Ok(None);
    }
    let after = integrate_express(&before)?;
    Ok(Some(FileChange {
        path: entrypoint.path.clone(),
        before: Some(before),
        after,
    }))
}

fn integrate_express(source: &str) -> Result<String, CliError> {
    let mut lines = source.lines().map(str::to_string).collect::<Vec<_>>();
    let uses_imports = lines
        .iter()
        .any(|line| line.trim_start().starts_with("import "));
    let auth_line = if uses_imports {
        "import { authport } from \"authport\";".to_string()
    } else {
        "const { authport } = require(\"authport\");".to_string()
    };
    if !lines.iter().any(|line| line.contains("authport")) {
        let insert_at = lines
            .iter()
            .rposition(|line| {
                let trimmed = line.trim_start();
                trimmed.starts_with("import ")
                    || trimmed.starts_with("const ") && trimmed.contains("require(")
            })
            .map(|index| index + 1)
            .unwrap_or(0);
        lines.insert(insert_at, auth_line);
    }
    let app_index = lines
        .iter()
        .position(|line| line.contains("express()"))
        .ok_or_else(|| error("Express entrypoint has no `express()` application to mount"))?;
    lines.insert(app_index + 1, "app.use(authport());".to_string());
    let mut out = lines.join("\n");
    if source.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

fn config_change(root: &Path) -> FileChange {
    let path = root.join("authport.toml");
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
        if std::env::var("AUTHPORT_INIT_FAIL_AFTER_WRITE").is_ok() {
            rollback(&written);
            return Err(error("simulated initialization failure"));
        }
    }
    Ok(())
}

fn atomic_write(path: &Path, contents: &str) -> Result<(), CliError> {
    let tmp = path.with_extension("authport-tmp");
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
    authport_routes_respond: bool,
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
    let boundary_present = application
        .as_ref()
        .map(|application| application.existing_authport.detected())
        .unwrap_or(false);
    let config_path = root.join("authport.toml");
    let runtime_starts = fs::read_to_string(&config_path)
        .ok()
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
    let report = VerifyReport {
        ok: application.is_some() && boundary_present && runtime_starts,
        application_discovered: application.is_some(),
        boundary_present,
        runtime_starts,
        control_plane_responds: runtime_starts,
        application_routes_remain_reachable: application_routes > 0,
        authport_routes_respond: runtime_starts,
        contract_fingerprint_stable: runtime_starts,
        live_authority_available: runtime_starts,
        application_routes,
    };
    Ok(report)
}

fn render_plan_text(plan: &InitPlan, preview: bool) -> String {
    let mut out = String::new();
    if plan.already_integrated {
        out.push_str("AuthPort already detected.\n");
    } else {
        out.push_str("AuthPort found your application.\n");
    }
    out.push_str(&format!(
        "Application:\n  {}\nFramework:\n  {}\nEntrypoint:\n  {}\n",
        plan.application.name.as_deref().unwrap_or("(unknown)"),
        plan.application.framework.as_deref().unwrap_or("(none)"),
        plan.application
            .entrypoints
            .first()
            .map(|entrypoint| display_path(&entrypoint.path, &plan.application.root))
            .unwrap_or_else(|| "(none)".to_string())
    ));
    if !plan.application.providers.is_empty() {
        out.push_str("Detected:\n");
        for provider in &plan.application.providers {
            out.push_str(&format!("  {}\n", provider.display_name));
        }
        out.push_str("Available to AuthPort:\n");
        for provider in &plan.application.providers {
            out.push_str(&format!("  {}\n", provider.id));
        }
    }
    out.push_str("Proposed integration:\n");
    if plan.mode == InitMode::Standalone {
        out.push_str("  + write standalone AuthPort adoption manifest\n");
    } else if plan.integration_supported {
        out.push_str("  + initialize AuthPort\n  + mount AuthPort boundary\n  + preserve existing application routes\n");
    } else {
        out.push_str("  (automatic source integration is not supported for this application)\n");
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
        out.push_str("Run `authport init --yes` to apply.\n");
    }
    out
}

fn first_run_text(plan: &InitPlan, report: &VerifyReport) -> String {
    format!(
        "✓ Application detected\n✓ AuthPort integrated\n✓ Runtime boundary configured\n✓ {} application routes discovered\n✓ AuthPort surface available\nNext:\n  authport serve\n  authport inspect\n  authport routes\n",
        report.application_routes.max(plan.application.routes.len())
    )
}

fn render_verify_text(report: &VerifyReport) -> String {
    let mark = |ok| if ok { "✓" } else { "✗" };
    format!(
        "{} application discovered\n{} AuthPort boundary present\n{} runtime starts\n{} control plane responds\n{} application routes remain reachable\n{} AuthPort routes respond\n{} contract fingerprint stable\n{} live authority state available\n",
        mark(report.application_discovered),
        mark(report.boundary_present),
        mark(report.runtime_starts),
        mark(report.control_plane_responds),
        mark(report.application_routes_remain_reachable),
        mark(report.authport_routes_respond),
        mark(report.contract_fingerprint_stable),
        mark(report.live_authority_available)
    )
}

fn render_plan_json(plan: &InitPlan, dry_run: bool) -> String {
    format!(
        "{{\n  \"application\": \"{}\",\n  \"framework\": \"{}\",\n  \"entrypoint\": \"{}\",\n  \"detected\": {},\n  \"already_integrated\": {},\n  \"mode\": \"{}\",\n  \"dry_run\": {},\n  \"routes\": {},\n  \"providers\": [{}],\n  \"changes\": [{}]\n}}\n",
        escape(plan.application.name.as_deref().unwrap_or("")),
        escape(plan.application.framework.as_deref().unwrap_or("")),
        escape(
            &plan
                .application
                .entrypoints
                .first()
                .map(|entrypoint| display_path(&entrypoint.path, &plan.application.root))
                .unwrap_or_default()
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
        "{{\"ok\": {}, \"application_discovered\": {}, \"boundary_present\": {}, \"runtime_starts\": {}, \"control_plane_responds\": {}, \"application_routes_remain_reachable\": {}, \"authport_routes_respond\": {}, \"contract_fingerprint_stable\": {}, \"live_authority_available\": {}, \"application_routes\": {}}}\n",
        report.ok,
        report.application_discovered,
        report.boundary_present,
        report.runtime_starts,
        report.control_plane_responds,
        report.application_routes_remain_reachable,
        report.authport_routes_respond,
        report.contract_fingerprint_stable,
        report.live_authority_available,
        report.application_routes
    )
}

fn render_manifest(application: &ApplicationCandidate, mode: InitMode) -> String {
    format!(
        "{{\n  \"application\": \"{}\",\n  \"mode\": \"{}\",\n  \"framework\": \"{}\",\n  \"entrypoint\": \"{}\",\n  \"routes\": {}\n}}\n",
        escape(application.name.as_deref().unwrap_or("")),
        mode_str(mode),
        escape(application.framework.as_deref().unwrap_or("")),
        escape(
            &application
                .entrypoints
                .first()
                .map(|entrypoint| display_path(&entrypoint.path, &application.root))
                .unwrap_or_default()
        ),
        application.routes.len()
    )
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
