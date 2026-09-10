//! Local, read-only Studio projection of repository authority state.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, RwLock};

use appport_auth_mesh_boundary::{AuthContext, BoundaryRequest, Method};
use appport_auth_mesh_discovery::discover;
use appport_auth_mesh_dsl::parse_auth_block;
use appport_auth_mesh_server::{
    ApplicationBinding, ApplicationUpstream, HttpRequest, HttpResponse, RouteOutcome,
    StudioController, UpstreamProxy,
};
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
    let surface = AuthSurface::derive(&config);
    let live_upstream =
        init::adoption_upstream(&root).filter(|upstream| init::upstream_reachable(upstream));
    let binding = Arc::new(StudioApplication::new(live_upstream.as_deref())?);
    let controller = Arc::new(RepositoryStudio::new(
        root.clone(),
        binding.clone(),
        surface,
    ));
    let options = serve::ServeOptions {
        address: address.clone(),
        studio_page: None,
        upstream: live_upstream,
        application_binding: Some(binding),
        studio_controller: Some(controller),
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

struct StudioApplication {
    proxy: RwLock<Option<UpstreamProxy>>,
    forwarded: Mutex<usize>,
}

impl StudioApplication {
    fn new(upstream: Option<&str>) -> Result<Self, CliError> {
        Ok(Self {
            proxy: RwLock::new(upstream.map(build_proxy).transpose()?),
            forwarded: Mutex::new(0),
        })
    }

    fn attach(&self, upstream: &str) -> Result<(), CliError> {
        *self
            .proxy
            .write()
            .map_err(|_| error("attachment lock poisoned"))? = Some(build_proxy(upstream)?);
        Ok(())
    }

    fn detach(&self) {
        if let Ok(mut proxy) = self.proxy.write() {
            *proxy = None;
        }
    }
}

fn build_proxy(upstream: &str) -> Result<UpstreamProxy, CliError> {
    let origin = ApplicationUpstream::parse(upstream).map_err(error)?;
    let mut options = serve::ServeOptions::default();
    options
        .public_paths
        .push("/__authboundry_attachment_probe".to_string());
    Ok(UpstreamProxy::new(
        origin,
        serve::application_policy(&options),
        options.proxy_secret,
    ))
}

impl ApplicationBinding for StudioApplication {
    fn resolve(&self, method: Method, path: &str) -> RouteOutcome {
        self.proxy
            .read()
            .ok()
            .and_then(|proxy| proxy.as_ref().map(|proxy| proxy.resolve(method, path)))
            .unwrap_or(RouteOutcome::NotFound)
    }

    fn handle(&self, request: &BoundaryRequest, context: Option<&AuthContext>) -> HttpResponse {
        let response = self
            .proxy
            .read()
            .ok()
            .and_then(|proxy| proxy.as_ref().map(|proxy| proxy.handle(request, context)))
            .unwrap_or_else(|| {
                HttpResponse::denied(503, "not_attached", "application is not attached")
            });
        if request.path == "/__authboundry_attachment_probe" && response.status < 500 {
            if let Ok(mut count) = self.forwarded.lock() {
                *count += 1;
            }
        }
        response
    }
}

struct RepositoryStudio {
    root: PathBuf,
    binding: Arc<StudioApplication>,
    proposals: Mutex<std::collections::BTreeMap<String, init::AttachmentPlan>>,
    surface: AuthSurface,
}

impl RepositoryStudio {
    fn new(root: PathBuf, binding: Arc<StudioApplication>, surface: AuthSurface) -> Self {
        Self {
            root,
            binding,
            proposals: Mutex::new(Default::default()),
            surface,
        }
    }

    fn field(request: &HttpRequest, name: &str) -> Option<String> {
        let source = String::from_utf8_lossy(&request.body);
        let marker = format!("\"{}\":", name);
        let value = source
            .split_once(&marker)?
            .1
            .trim_start()
            .strip_prefix('"')?;
        Some(value.split_once('"')?.0.to_string())
    }

    fn failure(status: u16, message: impl AsRef<str>) -> HttpResponse {
        HttpResponse::json(
            status,
            format!(
                "{{\"ok\":false,\"reason\":\"{}\"}}",
                json_escape(message.as_ref())
            ),
        )
    }
}

impl StudioController for RepositoryStudio {
    fn page(&self) -> Option<String> {
        Some(render(&self.root, &self.surface))
    }

    fn handle(&self, request: &HttpRequest) -> Option<HttpResponse> {
        let response = match (request.method, request.path.as_str()) {
            (Method::Get, "/_authboundry/application")
            | (Method::Get, "/_authboundry/application/attachment") => {
                let state = init::read_adoption(&self.root);
                let upstream = state
                    .as_ref()
                    .and_then(|state| state.upstream.as_deref())
                    .unwrap_or("");
                HttpResponse::json(
                    200,
                    format!(
                        "{{\"ok\":true,\"application\":\"{}\",\"upstream\":\"{}\",\"attached\":{},\"reachable\":{},\"routes\":{}}}",
                        json_escape(state.as_ref().map(|state| state.application.as_str()).unwrap_or("")),
                        json_escape(upstream),
                        !upstream.is_empty(),
                        init::upstream_reachable(upstream),
                        state.map(|state| state.routes).unwrap_or(0)
                    ),
                )
            }
            (Method::Post, "/_authboundry/application/discover") => {
                let supplied = Self::field(request, "upstream");
                let found = supplied
                    .filter(|url| init::upstream_reachable(url))
                    .or_else(|| {
                        init::adoption_upstream(&self.root)
                            .filter(|url| init::upstream_reachable(url))
                    })
                    .or_else(|| {
                        [3000, 3001, 5173, 8000, 8080, 9000]
                            .iter()
                            .map(|port| format!("http://127.0.0.1:{}", port))
                            .find(|url| init::upstream_reachable(url))
                    });
                HttpResponse::json(
                    200,
                    format!(
                        "{{\"ok\":true,\"upstream\":{},\"reachable\":{}}}",
                        found
                            .as_ref()
                            .map(|value| format!("\"{}\"", value))
                            .unwrap_or_else(|| "null".to_string()),
                        found.is_some()
                    ),
                )
            }
            (Method::Post, "/_authboundry/application/attachment/preview") => {
                let Some(upstream) = Self::field(request, "upstream") else {
                    return Some(Self::failure(400, "application upstream is required"));
                };
                match init::plan_attachment(&self.root, &upstream) {
                    Ok(plan) => {
                        let id = proposal_id(&plan);
                        let body = format!(
                            "{{\"ok\":true,\"proposal_id\":\"{}\",\"application\":\"{}\",\"upstream\":\"{}\",\"routes\":{},\"preview\":\"{}\"}}",
                            id,
                            json_escape(&plan.application),
                            json_escape(&plan.upstream),
                            plan.routes,
                            json_escape(&plan.preview)
                        );
                        self.proposals.lock().ok()?.insert(id, plan);
                        HttpResponse::json(200, body)
                    }
                    Err(err) => Self::failure(422, err.message),
                }
            }
            (Method::Post, "/_authboundry/application/attachment/apply") => {
                let Some(id) = Self::field(request, "proposal_id") else {
                    return Some(Self::failure(400, "proposal approval is required"));
                };
                let plan = self.proposals.lock().ok()?.remove(&id);
                match plan {
                    Some(plan) => match init::apply_attachment(&plan)
                        .and_then(|_| self.binding.attach(&plan.upstream))
                    {
                        Ok(()) => HttpResponse::json(200, "{\"ok\":true,\"attached\":true}"),
                        Err(err) => Self::failure(409, err.message),
                    },
                    None => Self::failure(409, "attachment proposal is missing or stale"),
                }
            }
            (Method::Post, "/_authboundry/application/attachment/test") => {
                let crossed = self
                    .binding
                    .forwarded
                    .lock()
                    .map(|count| *count > 0)
                    .unwrap_or(false);
                HttpResponse::json(
                    200,
                    format!("{{\"ok\":true,\"authboundry_reachable\":true,\"request_forwarded\":{},\"application_responded\":{},\"protected_routes_verified\":false}}", crossed, crossed),
                )
            }
            (Method::Post, "/_authboundry/application/attachment/detach") => {
                match init::detach_application(&self.root) {
                    Ok(()) => {
                        self.binding.detach();
                        HttpResponse::json(200, "{\"ok\":true,\"attached\":false}")
                    }
                    Err(err) => Self::failure(409, err.message),
                }
            }
            _ => return None,
        };
        Some(response)
    }
}

fn proposal_id(plan: &init::AttachmentPlan) -> String {
    use std::hash::{Hash, Hasher};
    let mut value = std::collections::hash_map::DefaultHasher::new();
    plan.before.hash(&mut value);
    plan.upstream.hash(&mut value);
    format!("attachment-{:016x}", value.finish())
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
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
    let configured = upstream.is_some();
    let reachable = upstream.map(init::upstream_reachable).unwrap_or(false);
    let routes = app.as_ref().map(|app| app.routes.as_slice()).unwrap_or(&[]);
    let route_rows = if routes.is_empty() {
        format!(
            "<p class=muted>No application routes discovered.<br>{}</p>",
            if configured {
                "Attachment is configured independently of route discovery."
            } else {
                "Application is not currently attached."
            }
        )
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
:root{{color-scheme:dark;background:#0b0d10;color:#edf0f4;font:15px/1.5 system-ui,sans-serif}}body{{margin:0}}header{{padding:24px 32px;border-bottom:1px solid #292d35}}header b{{font-size:20px}}header span,.muted{{color:#99a1ad}}main{{max-width:920px;margin:auto;padding:36px 24px}}h1{{font-size:30px;margin:0 0 4px}}h2{{font-size:16px;margin:32px 0 12px}}.card{{background:#13171d;border:1px solid #292d35;border-radius:12px;padding:24px;margin:16px 0}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}}dt{{color:#99a1ad}}dd{{margin:4px 0;font-weight:650}}.ok{{color:#55d187}}.warn{{color:#f4bd61}}.off{{color:#99a1ad}}button{{background:#edf0f4;color:#101318;border:0;border-radius:7px;padding:10px 16px;font-weight:700;margin-right:8px;cursor:pointer}}button.secondary{{background:#292d35;color:#edf0f4}}input{{padding:10px;border:1px solid #3b414c;border-radius:7px;background:#0b0d10;color:#edf0f4;width:min(420px,90%);margin:8px 0}}pre{{white-space:pre-wrap}}dialog{{background:#13171d;color:#edf0f4;border:1px solid #3b414c;border-radius:12px;width:min(620px,90vw)}}table{{width:100%;border-collapse:collapse}}td{{padding:9px;border-bottom:1px solid #292d35}}</style></head><body>
<header><b>AuthBoundry</b><br><span>Authority Boundary · Studio</span><nav>Overview · Application · Authority · Routes · Providers · Sessions · Policies · Audit · Attachment</nav></header><main><h1>{name}</h1><p class="muted">What AuthBoundry currently knows and protects.</p>
<section class="card grid"><dl><dt>Authority</dt><dd class="ok">✓ Configured</dd></dl><dl><dt>Application</dt><dd class="{attach_class}">{application}</dd></dl><dl><dt>Protection</dt><dd class="{protect_class}">{protection}</dd></dl><dl><dt>Mode</dt><dd>Standalone</dd></dl></section>
{attach_callout}<h2>Topology</h2><section class="card grid"><dl><dt>Studio + runtime</dt><dd id="studio-origin"></dd></dl><dl><dt>Protected application upstream</dt><dd>{upstream}</dd></dl></section><h2>Application</h2><section class="card grid"><dl><dt>Language</dt><dd>{language}</dd></dl><dl><dt>Framework</dt><dd>{framework}</dd></dl><dl><dt>Package manager</dt><dd>{package_manager}</dd></dl><dl><dt>Entrypoint</dt><dd>{entrypoint}</dd></dl><dl><dt>Run command</dt><dd>{run_command}</dd></dl><dl><dt>Upstream</dt><dd>{upstream}</dd></dl></section>
<h2>Authority</h2><section class="card grid"><dl><dt>Providers</dt><dd>{providers}</dd></dl><dl><dt>Principals</dt><dd>Human · Service</dd></dl><dl><dt>Agents / Delegation</dt><dd>Disabled</dd></dl><dl><dt>Sessions · Policies · Audit</dt><dd>Runtime authority</dd></dl></section>
<h2>Routes</h2><section class="card"><table>{route_rows}</table></section><h2>Contract</h2><p class="muted">{fingerprint}</p></main>
<dialog id="attach-dialog"><h2>Attach Application</h2><div id="attach-step"><p>Find a reachable application runtime. Reachability will not attach it.</p><label>Application upstream<br><input id="upstream" value="{upstream_input}" placeholder="http://127.0.0.1:3000"></label><p id="attach-status" class="muted"></p><button id="discover">Discover</button><button id="test-connection" class="secondary">Test Connection</button><button id="preview">Preview Attachment</button></div><div id="approval" hidden><h2>Attachment Preview</h2><pre id="preview-text"></pre><button id="cancel" class="secondary">Cancel</button><button id="approve">Approve Attachment</button></div></dialog>
<script>
const dialog=document.getElementById('attach-dialog'), status=document.getElementById('attach-status'), input=document.getElementById('upstream'); let proposal=null;
document.getElementById('studio-origin').textContent=location.origin;
const post=async(path,body={{}})=>{{const response=await fetch(path,{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify(body)}});const data=await response.json();if(!response.ok||data.ok===false)throw new Error(data.reason||'Request failed');return data}};
document.getElementById('open-attachment').onclick=()=>dialog.showModal();
document.getElementById('discover').onclick=async()=>{{status.textContent='Discovering reachable runtimes…';try{{const data=await post('/_authboundry/application/discover');if(data.reachable){{input.value=data.upstream;status.textContent='✓ Application reachable';status.className='ok'}}else{{status.textContent='No running application was detected.';status.className='warn'}}}}catch(error){{status.textContent=error.message;status.className='warn'}}}};
document.getElementById('test-connection').onclick=async()=>{{status.textContent='Testing connection…';try{{const data=await post('/_authboundry/application/discover',{{upstream:input.value}});if(!data.reachable)throw new Error('Application not reachable. Start the application or change the upstream.');status.textContent='✓ Application reachable (not attached yet)';status.className='ok'}}}}catch(error){{status.textContent=error.message;status.className='warn'}}}};
document.getElementById('preview').onclick=async()=>{{status.textContent='Validating attachment…';try{{proposal=await post('/_authboundry/application/attachment/preview',{{upstream:input.value}});document.getElementById('preview-text').textContent=proposal.preview;document.getElementById('attach-step').hidden=true;document.getElementById('approval').hidden=false}}catch(error){{status.textContent=error.message;status.className='warn'}}}};
document.getElementById('cancel').onclick=()=>{{proposal=null;document.getElementById('approval').hidden=true;document.getElementById('attach-step').hidden=false;status.textContent='Attachment cancelled. No changes were made.'}};
document.getElementById('approve').onclick=async()=>{{try{{await post('/_authboundry/application/attachment/apply',{{proposal_id:proposal.proposal_id}});await fetch('/__authboundry_attachment_probe').catch(()=>{{}});const result=await post('/_authboundry/application/attachment/test');status.textContent=result.request_forwarded?'✓ Attachment configured\n✓ Request crossed AuthBoundry\nBasic attachment verified.\nProtected-route verification unavailable until routes are discovered.':'Attachment configured; boundary request was not verified.';setTimeout(()=>location.reload(),900)}}catch(error){{document.getElementById('approval').hidden=true;document.getElementById('attach-step').hidden=false;status.textContent='Attachment failed. No partial attachment was recorded.\n'+error.message;status.className='warn'}}}};
document.getElementById('detach')?.addEventListener('click',async()=>{{if(confirm('Detach this application?')){{await post('/_authboundry/application/attachment/detach');location.reload()}}}});
document.getElementById('test-boundary')?.addEventListener('click',async()=>{{await fetch('/__authboundry_attachment_probe').catch(()=>{{}});const result=await post('/_authboundry/application/attachment/test');alert(result.request_forwarded?'Basic attachment verified. Request crossed AuthBoundry.':'Boundary request was not verified.')}});
</script></body></html>"#,
        name = esc(name),
        attach_class = if configured { "ok" } else { "warn" },
        application = if configured {
            "✓ Attached"
        } else {
            "⚠ Not attached"
        },
        protect_class = if reachable { "ok" } else { "off" },
        protection = if reachable {
            "✓ Active"
        } else if configured {
            "○ Inactive · upstream unreachable"
        } else {
            "○ Inactive"
        },
        attach_callout = if upstream.is_none() {
            "<section class=\"card\"><h2>Attach Application</h2><p>AuthBoundry discovered this application but has not connected to its runtime.</p><button id=\"open-attachment\">Attach Application</button></section>"
        } else {
            "<section class=\"card\"><h2>Application Boundary</h2><button id=\"test-boundary\">Test Boundary</button><button id=\"detach\" class=\"secondary\">Detach</button></section>"
        },
        upstream_input = esc(upstream.unwrap_or("")),
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
        assert!(html.contains("id=\"open-attachment\""));
        assert!(html.contains("/_authboundry/application/attachment/preview"));
        assert!(html.contains("Approve Attachment"));
        assert!(!html.contains("authboundry attach --upstream"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn studio_preview_apply_and_detach_use_the_canonical_attachment_plan() {
        use std::collections::BTreeMap;
        use std::net::TcpListener;

        let root = std::env::temp_dir().join(format!(
            "authboundry-studio-attachment-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".authboundry")).unwrap();
        std::fs::write(root.join("package.json"), r#"{"name":"sample-app"}"#).unwrap();
        std::fs::write(
            root.join("authboundry.toml"),
            "use auth { providers = [local] }\n",
        )
        .unwrap();
        std::fs::write(root.join(".authboundry/adoption.json"), r#"{"application":"sample-app","mode":"standalone","authority":"configured","attachment":"none","protection":"inactive","upstream":"","routes":0}"#).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream = format!("http://localhost:{}", listener.local_addr().unwrap().port());
        std::thread::spawn(move || loop {
            if listener.accept().is_err() {
                break;
            }
        });
        let surface =
            AuthSurface::derive(&parse_auth_block("use auth { providers = [local] }\n").unwrap());
        let binding = Arc::new(StudioApplication::new(None).unwrap());
        let controller = RepositoryStudio::new(root.clone(), binding, surface);
        let request = |path: &str, body: String| {
            HttpRequest::assemble(
                Method::Post,
                path.to_string(),
                BTreeMap::from([("content-type".to_string(), "application/json".to_string())]),
                body.into_bytes(),
            )
        };

        let preview = controller
            .handle(&request(
                "/_authboundry/application/attachment/preview",
                format!(r#"{{"upstream":"{}"}}"#, upstream),
            ))
            .unwrap();
        assert_eq!(preview.status, 200);
        let body = String::from_utf8(preview.body).unwrap();
        let id = body
            .split_once("\"proposal_id\":\"")
            .unwrap()
            .1
            .split_once('"')
            .unwrap()
            .0;
        let applied = controller
            .handle(&request(
                "/_authboundry/application/attachment/apply",
                format!(r#"{{"proposal_id":"{}"}}"#, id),
            ))
            .unwrap();
        assert_eq!(applied.status, 200);
        assert_eq!(
            init::adoption_upstream(&root).as_deref(),
            Some(upstream.as_str())
        );
        assert!(controller.page().unwrap().contains("✓ Attached"));

        let detached = controller
            .handle(&request(
                "/_authboundry/application/attachment/detach",
                "{}".to_string(),
            ))
            .unwrap();
        assert_eq!(detached.status, 200);
        assert!(init::adoption_upstream(&root).is_none());
        assert!(controller.page().unwrap().contains("⚠ Not attached"));
        let _ = std::fs::remove_dir_all(root);
    }
}
