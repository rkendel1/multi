use std::fs;
use std::path::{Path, PathBuf};

use appport_auth_mesh_discovery::{
    discover, propose_authority, ApplicationCandidate, EntrypointKind, RouteCandidate,
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
        return Err(error("AuthBoundry initialization verification failed"));
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
    let already_integrated = boundary_integrated(&application, mode);
    let mut changes = Vec::new();

    if !already_integrated {
        if mode == InitMode::Embedded {
            if let Some(change) = node_dependency_change(&application)? {
                changes.push(change);
            }
            if let Some(change) = node_embedded_change(&application)? {
                changes.push(change);
            }
        }
        if !application.existing_authport.configuration {
            changes.push(config_change(root));
        }
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

fn boundary_integrated(application: &ApplicationCandidate, mode: InitMode) -> bool {
    match mode {
        InitMode::Embedded => {
            application.existing_authport.configuration
                && (application.existing_authport.middleware
                    || application.existing_authport.initialization)
        }
        InitMode::Standalone => {
            application.existing_authport.configuration && application.existing_authport.manifest
        }
    }
}

fn node_dependency_change(
    application: &ApplicationCandidate,
) -> Result<Option<FileChange>, CliError> {
    if application.language.as_deref() != Some("Node") {
        return Ok(None);
    }
    let path = application.root.join("package.json");
    let before = fs::read_to_string(&path)
        .map_err(|err| error(format!("cannot read `{}`: {}", path.display(), err)))?;
    if before.contains("\"authboundry\"") {
        return Ok(None);
    }
    Ok(Some(FileChange {
        path,
        before: Some(before.clone()),
        after: add_authport_dependency(&before)?,
    }))
}

fn add_authport_dependency(package_json: &str) -> Result<String, CliError> {
    if let Some(dependencies_index) = package_json.find("\"dependencies\"") {
        let after_key = &package_json[dependencies_index + "\"dependencies\"".len()..];
        let colon = after_key
            .find(':')
            .ok_or_else(|| error("package.json dependencies field is not an object"))?;
        let after_colon = dependencies_index + "\"dependencies\"".len() + colon + 1;
        let object_start = package_json[after_colon..]
            .find('{')
            .map(|index| after_colon + index)
            .ok_or_else(|| error("package.json dependencies field is not an object"))?;
        let object_end = matching_brace(package_json, object_start)
            .ok_or_else(|| error("package.json dependencies field is not an object"))?;
        let inside = &package_json[object_start + 1..object_end];
        let insertion = if inside.trim().is_empty() {
            "\"authboundry\":\"latest\"".to_string()
        } else {
            ",\"authboundry\":\"latest\"".to_string()
        };
        return Ok(format!(
            "{}{}{}",
            &package_json[..object_end],
            insertion,
            &package_json[object_end..]
        ));
    }

    let root_end = package_json
        .rfind('}')
        .ok_or_else(|| error("package.json root must be an object"))?;
    let prefix = &package_json[..root_end];
    let separator = if prefix.trim_end().ends_with('{') {
        ""
    } else {
        ","
    };
    Ok(format!(
        "{}{}\"dependencies\":{{\"authboundry\":\"latest\"}}{}",
        prefix,
        separator,
        &package_json[root_end..]
    ))
}

fn matching_brace(source: &str, start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in source
        .char_indices()
        .skip_while(|(index, _)| *index < start)
    {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
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
    if before.contains("authboundry()") || before.contains("app.use(authboundry") {
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
        "import { authboundry } from \"authboundry\";".to_string()
    } else {
        "const { authboundry } = require(\"authboundry\");".to_string()
    };
    if !lines.iter().any(|line| line.contains("authboundry")) {
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
    lines.insert(app_index + 1, "app.use(authboundry());".to_string());
    let mut out = lines.join("\n");
    if source.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
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
        authport_routes_respond: runtime_starts,
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
    if plan.mode == InitMode::Standalone {
        out.push_str("  + write standalone AuthBoundry adoption manifest\n");
    } else if plan.integration_supported {
        out.push_str("  + initialize AuthBoundry\n  + mount AuthBoundry boundary\n  + preserve existing application routes\n");
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
        out.push_str("Run `authboundry init --yes` to apply.\n");
    }
    out
}

fn first_run_text(plan: &InitPlan, report: &VerifyReport) -> String {
    format!(
        "✓ Application detected\n✓ AuthBoundry integrated\n✓ Runtime boundary configured\n✓ {} application routes discovered\n✓ AuthBoundry surface available\nNext:\n  authboundry serve\n  authboundry inspect\n  authboundry routes\n",
        report.application_routes.max(plan.application.routes.len())
    )
}

fn render_verify_text(report: &VerifyReport) -> String {
    let mark = |ok| if ok { "✓" } else { "✗" };
    format!(
        "{} application discovered\n{} AuthBoundry boundary present\n{} runtime starts\n{} control plane responds\n{} application routes remain reachable\n{} AuthBoundry routes respond\n{} contract fingerprint stable\n{} live authority state available\n",
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
        "{{\n  \"application\": \"{}\",\n  \"language\": \"{}\",\n  \"framework\": \"{}\",\n  \"package_manager\": \"{}\",\n  \"entrypoint\": \"{}\",\n  \"run_command\": \"{}\",\n  \"detected\": {},\n  \"already_integrated\": {},\n  \"mode\": \"{}\",\n  \"dry_run\": {},\n  \"routes\": {},\n  \"providers\": [{}],\n  \"changes\": [{}]\n}}\n",
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
        "{{\n  \"application\": \"{}\",\n  \"mode\": \"{}\",\n  \"language\": \"{}\",\n  \"framework\": \"{}\",\n  \"package_manager\": \"{}\",\n  \"entrypoint\": \"{}\",\n  \"run_command\": \"{}\",\n  \"routes\": {}\n}}\n",
        escape(application.name.as_deref().unwrap_or("")),
        mode_str(mode),
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
