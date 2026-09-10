//! Local, read-only Studio projection of repository authority state.

use std::path::PathBuf;
use std::process::Command;

use appport_auth_mesh_discovery::discover;
use appport_auth_mesh_dsl::parse_auth_block;
use appport_auth_mesh_surface::AuthSurface;

use crate::{error, init, serve, CliError, Output};

pub fn run(args: &[String]) -> Result<Output, CliError> {
    let mut root = None;
    let mut no_open = false;
    let mut address = "127.0.0.1:8787".to_string();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--no-open" => no_open = true,
            "--addr" => {
                index += 1;
                address = args
                    .get(index)
                    .ok_or_else(|| error("--addr needs a value"))?
                    .clone();
            }
            flag if flag.starts_with('-') => return Err(error(format!("unknown flag `{}`", flag))),
            value => root = Some(PathBuf::from(value)),
        }
        index += 1;
    }
    let root = root.unwrap_or(std::env::current_dir().map_err(|err| error(err.to_string()))?);
    let config_path = crate::DEFAULT_FILES
        .iter()
        .map(|name| root.join(name))
        .find(|path| path.exists())
        .ok_or_else(|| error("no authboundry.toml found; run `authboundry init` first"))?;
    let source = std::fs::read_to_string(&config_path).map_err(|err| error(err.to_string()))?;
    let config = parse_auth_block(&source).map_err(|err| error(err.message))?;
    let page = render(&root, &AuthSurface::derive(&config));
    let live_upstream =
        init::adoption_upstream(&root).filter(|upstream| init::upstream_reachable(upstream));
    let options = serve::ServeOptions {
        address: address.clone(),
        studio_page: Some(page),
        upstream: live_upstream,
        ..Default::default()
    };
    let running = serve::start(config, &options)?;
    let url = format!("http://{}", running.authport.address());
    println!("✓ Studio listening on {}", url);
    if !no_open {
        if open_browser(&url) {
            println!("Opening browser...");
        } else {
            println!("Open the URL above to continue.");
        }
    }
    running.authport.wait();
    Ok(Output {
        text: String::new(),
    })
}

fn open_browser(url: &str) -> bool {
    let mut command = if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else if cfg!(target_os = "windows") {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    command.spawn().is_ok()
}

fn render(root: &std::path::Path, surface: &AuthSurface) -> String {
    let app = discover(root);
    let adoption = init::read_adoption(root);
    let name = adoption
        .as_ref()
        .map(|state| state.application.as_str())
        .filter(|v| !v.is_empty())
        .or_else(|| app.as_ref().and_then(|app| app.name.as_deref()))
        .unwrap_or("Unknown application");
    let upstream = adoption
        .as_ref()
        .and_then(|state| state.upstream.as_deref());
    let attached = upstream.map(init::upstream_reachable).unwrap_or(false);
    let routes = app.as_ref().map(|app| app.routes.as_slice()).unwrap_or(&[]);
    let route_rows = if routes.is_empty() {
        "<p class=muted>No application routes discovered.<br>Application is not currently attached.</p>".to_string()
    } else {
        routes
            .iter()
            .map(|r| {
                format!(
                    "<tr><td>{} {}</td><td>Discovered</td></tr>",
                    esc(&r.method),
                    esc(&r.path)
                )
            })
            .collect()
    };
    let providers = surface
        .providers
        .iter()
        .map(|p| esc(&p.display_name))
        .collect::<Vec<_>>()
        .join(", ");
    let detail = |value: Option<&str>| esc(value.unwrap_or("Unknown"));
    let language = detail(app.as_ref().and_then(|value| value.language.as_deref()));
    let framework = detail(app.as_ref().and_then(|value| value.framework.as_deref()));
    let package_manager = detail(
        app.as_ref()
            .and_then(|value| value.package_manager.as_deref()),
    );
    let entrypoint = detail(
        app.as_ref()
            .and_then(|value| value.entrypoints.first())
            .and_then(|value| value.path.to_str()),
    );
    let run_command = detail(
        app.as_ref()
            .and_then(|value| value.servers.first())
            .map(|value| value.command.as_str()),
    );
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AuthBoundry Studio</title><style>
:root{{color-scheme:dark;background:#0b0d10;color:#edf0f4;font:15px/1.5 system-ui,sans-serif}}body{{margin:0}}header{{padding:24px 32px;border-bottom:1px solid #292d35}}header b{{font-size:20px}}header span,.muted{{color:#99a1ad}}main{{max-width:920px;margin:auto;padding:36px 24px}}h1{{font-size:30px;margin:0 0 4px}}h2{{font-size:16px;margin:32px 0 12px}}.card{{background:#13171d;border:1px solid #292d35;border-radius:12px;padding:24px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}}dt{{color:#99a1ad}}dd{{margin:4px 0;font-weight:650}}.ok{{color:#55d187}}.warn{{color:#f4bd61}}.off{{color:#99a1ad}}button{{background:#edf0f4;color:#101318;border:0;border-radius:7px;padding:10px 16px;font-weight:700}}table{{width:100%;border-collapse:collapse}}td{{padding:9px;border-bottom:1px solid #292d35}}</style></head><body>
<header><b>AuthBoundry</b><br><span>Authority Boundary · Studio</span><nav>Overview · Application · Authority · Routes · Providers · Sessions · Policies · Audit · Attachment</nav></header><main><h1>{name}</h1><p class="muted">What AuthBoundry currently knows and protects.</p>
<section class="card grid"><dl><dt>Authority</dt><dd class="ok">✓ Configured</dd></dl><dl><dt>Application</dt><dd class="{attach_class}">{application}</dd></dl><dl><dt>Protection</dt><dd class="{protect_class}">{protection}</dd></dl><dl><dt>Mode</dt><dd>Standalone</dd></dl></section>
{attach_callout}<h2>Application</h2><section class="card grid"><dl><dt>Language</dt><dd>{language}</dd></dl><dl><dt>Framework</dt><dd>{framework}</dd></dl><dl><dt>Package manager</dt><dd>{package_manager}</dd></dl><dl><dt>Entrypoint</dt><dd>{entrypoint}</dd></dl><dl><dt>Run command</dt><dd>{run_command}</dd></dl><dl><dt>Upstream</dt><dd>{upstream}</dd></dl></section>
<h2>Authority</h2><section class="card grid"><dl><dt>Providers</dt><dd>{providers}</dd></dl><dl><dt>Principals</dt><dd>Human · Service</dd></dl><dl><dt>Agents / Delegation</dt><dd>Disabled</dd></dl><dl><dt>Sessions · Policies · Audit</dt><dd>Runtime authority</dd></dl></section>
<h2>Routes</h2><section class="card"><table>{route_rows}</table></section><h2>Contract</h2><p class="muted">{fingerprint}</p></main></body></html>"#,
        name = esc(name),
        attach_class = if attached { "ok" } else { "warn" },
        application = if attached {
            "✓ Attached"
        } else {
            "⚠ Not attached"
        },
        protect_class = if attached { "ok" } else { "off" },
        protection = if attached {
            "✓ Active"
        } else {
            "○ Inactive"
        },
        attach_callout = if upstream.is_none() {
            "<section class=\"card\"><h2>Attach Application</h2><p>AuthBoundry discovered this application but has not connected to its runtime.</p><p class=muted>Preview and approve attachment with:<br><code>authboundry attach --upstream http://127.0.0.1:PORT</code></p><button disabled>Attach Application</button></section>"
        } else {
            ""
        },
        upstream = esc(upstream.unwrap_or("Not configured")),
        providers = if providers.is_empty() {
            "None".into()
        } else {
            providers
        },
        route_rows = route_rows,
        fingerprint = esc(&surface.contract_fingerprint),
        language = language,
        framework = framework,
        package_manager = package_manager,
        entrypoint = entrypoint,
        run_command = run_command
    )
}

fn esc(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_run_page_truthfully_reports_an_unattached_application() {
        let root = std::env::temp_dir().join(format!("authboundry-studio-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".authboundry")).unwrap();
        std::fs::write(root.join("package.json"), r#"{"name":"sample-app"}"#).unwrap();
        std::fs::write(
            root.join("authboundry.toml"),
            "use auth { providers = [local] }\n",
        )
        .unwrap();
        std::fs::write(root.join(".authboundry/adoption.json"), r#"{"application":"sample-app","mode":"standalone","attachment":"none","upstream":"","routes":0}"#).unwrap();
        let config = parse_auth_block("use auth { providers = [local] }\n").unwrap();
        let html = render(&root, &AuthSurface::derive(&config));
        assert!(html.contains("sample-app"));
        assert!(html.contains("✓ Configured"));
        assert!(html.contains("⚠ Not attached"));
        assert!(html.contains("○ Inactive"));
        assert!(html.contains("No application routes discovered"));
        assert!(html.contains("authboundry attach --upstream"));
        let _ = std::fs::remove_dir_all(root);
    }
}
