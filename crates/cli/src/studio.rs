//! Local, read-only Studio projection of repository authority state.

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, RwLock};

use appport_auth_mesh_boundary::{AuthContext, AuthPortRuntime, BoundaryRequest, Method};
use appport_auth_mesh_discovery::discover;
use appport_auth_mesh_dsl::parse_auth_block;
use appport_auth_mesh_server::{
    ApplicationBinding, ApplicationUpstream, HttpRequest, HttpResponse, RouteOutcome,
    StudioController, UpstreamProxy,
};
use appport_auth_mesh_surface::AuthSurface;

use crate::{error, init, serve, CliError, Output};

const ROUTE_ACCESS_FILE: &str = ".authboundry/route-access.json";

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
    let binding = Arc::new(StudioApplication::new(&root, live_upstream.as_deref())?);
    let controller = Arc::new(RepositoryStudio::new(
        root.clone(),
        binding.clone(),
        surface,
    ));
    let options = serve::ServeOptions {
        address: address.clone(),
        accounts: init::development_accounts(&root),
        tenants: vec!["development".to_string()],
        proxy_secret: init::development_proxy_secret(&root).unwrap_or_default(),
        grants: development_route_grants(&root),
        studio_page: None,
        upstream: live_upstream,
        application_binding: Some(binding),
        studio_controller: Some(controller),
        development_mail_dir: Some(root.join(".authboundry/mail")),
        ..Default::default()
    };
    let running = serve::start(config, &options)?;
    let url = format!("http://{}/_authboundry/studio", running.authport.address());
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
    root: PathBuf,
    secret: String,
    proxy: RwLock<Option<UpstreamProxy>>,
    forwarded: Mutex<usize>,
}

impl StudioApplication {
    fn new(root: &std::path::Path, upstream: Option<&str>) -> Result<Self, CliError> {
        let secret = init::development_proxy_secret(root).unwrap_or_default();
        Ok(Self {
            root: root.to_path_buf(),
            proxy: RwLock::new(
                upstream
                    .map(|value| build_proxy(root, value, &secret))
                    .transpose()?,
            ),
            secret,
            forwarded: Mutex::new(0),
        })
    }

    fn attach(&self, upstream: &str) -> Result<(), CliError> {
        *self
            .proxy
            .write()
            .map_err(|_| error("attachment lock poisoned"))? =
            Some(build_proxy(&self.root, upstream, &self.secret)?);
        Ok(())
    }

    fn detach(&self) {
        if let Ok(mut proxy) = self.proxy.write() {
            *proxy = None;
        }
    }

    fn sync(&self, upstream: Option<&str>) {
        match upstream {
            Some(value) if init::upstream_reachable(value) => {
                if let Ok(proxy) = build_proxy(&self.root, value, &self.secret) {
                    if let Ok(mut current) = self.proxy.write() {
                        *current = Some(proxy);
                    }
                }
            }
            _ => self.detach(),
        }
    }
}

fn build_proxy(
    root: &std::path::Path,
    upstream: &str,
    secret: &str,
) -> Result<UpstreamProxy, CliError> {
    let origin = ApplicationUpstream::parse(upstream).map_err(error)?;
    let mut options = serve::ServeOptions::default();
    options
        .public_paths
        .push("/__authboundry_attachment_probe".to_string());
    options.public_paths.extend(
        ["/assets/", "/@vite/", "/src/", "/node_modules/", "/favicon"]
            .into_iter()
            .map(str::to_string),
    );
    if let Some(routes) = init::discovered_routes(root) {
        options.public_exact.extend(
            routes
                .into_iter()
                .filter(|route| init::is_public_entry_path(&route.path))
                .map(|route| route.path),
        );
    }
    for entry in route_access(root) {
        if entry.access != "default" {
            options.required_exact.push((
                entry.path.clone(),
                route_capability(&entry.method, &entry.path, &entry.access),
            ));
        }
    }
    Ok(UpstreamProxy::new(
        origin,
        serve::application_policy(&options),
        secret.to_string(),
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

    fn upgrade(
        &self,
        request: &HttpRequest,
        context: Option<&AuthContext>,
        stream: TcpStream,
    ) -> bool {
        self.proxy
            .read()
            .ok()
            .and_then(|proxy| {
                proxy
                    .as_ref()
                    .map(|proxy| proxy.upgrade(request, context, stream))
            })
            .unwrap_or(false)
    }
}

struct RepositoryStudio {
    root: PathBuf,
    binding: Arc<StudioApplication>,
    proposals: Mutex<std::collections::BTreeMap<String, init::AttachmentPlan>>,
    surface: AuthSurface,
    runtime: RwLock<Option<Arc<AuthPortRuntime>>>,
}

impl RepositoryStudio {
    fn new(root: PathBuf, binding: Arc<StudioApplication>, surface: AuthSurface) -> Self {
        Self {
            root,
            binding,
            proposals: Mutex::new(Default::default()),
            surface,
            runtime: RwLock::new(None),
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
    fn attach_runtime(&self, runtime: Arc<AuthPortRuntime>) {
        if let Ok(mut current) = self.runtime.write() {
            *current = Some(runtime);
        }
    }

    fn page(&self) -> Option<String> {
        let upstream = init::adoption_upstream(&self.root);
        self.binding.sync(upstream.as_deref());
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
                let probe = BoundaryRequest::get("/__authboundry_attachment_probe");
                let upstream_response = self.binding.handle(&probe, None);
                let crossed = upstream_response.status < 500;
                HttpResponse::json(
                    200,
                    format!("{{\"ok\":{},\"authboundry_reachable\":true,\"request_forwarded\":{},\"application_responded\":{},\"upstream_status\":{},\"protected_routes_verified\":false}}", crossed, crossed, crossed, upstream_response.status),
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
            (Method::Post, "/_authboundry/application/routes/access") => {
                let Some(method) = Self::field(request, "method") else {
                    return Some(Self::failure(400, "route method is required"));
                };
                let Some(path) = Self::field(request, "path") else {
                    return Some(Self::failure(400, "route path is required"));
                };
                let Some(access) = Self::field(request, "access") else {
                    return Some(Self::failure(400, "route access is required"));
                };
                match save_route_access(&self.root, &method, &path, &access) {
                    Ok(()) => {
                        self.binding
                            .sync(init::adoption_upstream(&self.root).as_deref());
                        HttpResponse::json(200, "{\"ok\":true,\"persisted\":true}")
                    }
                    Err(err) => Self::failure(422, err.message),
                }
            }
            (Method::Post, "/_authboundry/application/users") => {
                let Some(username) = Self::field(request, "username") else {
                    return Some(Self::failure(400, "username is required"));
                };
                let Some(password) = Self::field(request, "password") else {
                    return Some(Self::failure(400, "password is required"));
                };
                let role = Self::field(request, "role").unwrap_or_else(|| "user".to_string());
                if !matches!(role.as_str(), "admin" | "user") {
                    return Some(Self::failure(400, "role must be admin or user"));
                }
                let email = Self::field(request, "email").filter(|value| !value.trim().is_empty());
                let Some(runtime) = self.runtime.read().ok()?.clone() else {
                    return Some(Self::failure(503, "authority runtime is unavailable"));
                };
                let mut claims =
                    std::collections::BTreeMap::from([("role".to_string(), role.clone())]);
                if let Some(email) = &email {
                    claims.insert("email".to_string(), email.clone());
                }
                match runtime.create_local_user(
                    "development",
                    &username,
                    &password,
                    email.as_deref(),
                    claims.clone(),
                ) {
                    Ok(()) => {
                        let account = serve::Account {
                            tenant: "development".to_string(),
                            username,
                            password,
                            claims,
                        };
                        match persist_development_account(&self.root, account) {
                            Ok(()) => HttpResponse::json(201, "{\"ok\":true,\"created\":true}"),
                            Err(err) => Self::failure(500, err.message),
                        }
                    }
                    Err(err) => Self::failure(422, err.message),
                }
            }
            _ => return None,
        };
        Some(response)
    }
}

#[derive(Clone)]
struct RouteAccess {
    method: String,
    path: String,
    access: String,
}

fn persist_development_account(
    root: &std::path::Path,
    account: serve::Account,
) -> Result<(), CliError> {
    let mut accounts = init::development_accounts(root);
    if accounts
        .iter()
        .any(|existing| existing.username == account.username)
    {
        return Err(error(format!("user `{}` already exists", account.username)));
    }
    accounts.push(account);
    let proxy_secret = init::development_proxy_secret(root).unwrap_or_default();
    let rows = accounts
        .iter()
        .map(|account| {
            let claims = account
                .claims
                .iter()
                .map(|(key, value)| format!("{}={}", key, value))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "    {{\"username\": \"{}\", \"password\": \"{}\", \"claims\": \"{}\"}}",
                json_escape(&account.username),
                json_escape(&account.password),
                json_escape(&claims)
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    std::fs::write(
        root.join(".authboundry/development.json"),
        format!(
            "{{\n  \"tenant\": \"development\",\n  \"proxy_secret\": \"{}\",\n  \"accounts\": [\n{}\n  ]\n}}\n",
            json_escape(&proxy_secret), rows
        ),
    )
    .map_err(|err| error(format!("cannot persist development user: {err}")))
}

fn route_access(root: &std::path::Path) -> Vec<RouteAccess> {
    let Ok(source) = std::fs::read_to_string(root.join(ROUTE_ACCESS_FILE)) else {
        return Vec::new();
    };
    source
        .lines()
        .filter(|line| line.contains("\"method\""))
        .filter_map(|line| {
            Some(RouteAccess {
                method: json_line_field(line, "method")?,
                path: json_line_field(line, "path")?,
                access: json_line_field(line, "access")?,
            })
        })
        .collect()
}

fn json_line_field(line: &str, field: &str) -> Option<String> {
    let marker = format!("\"{}\":\"", field);
    Some(line.split_once(&marker)?.1.split_once('"')?.0.to_string())
}

fn development_mail_rows(root: &std::path::Path) -> String {
    let Ok(entries) = std::fs::read_dir(root.join(".authboundry/mail")) else {
        return "<tr><td colspan=3>No development messages yet.</td></tr>".to_string();
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();
    paths.reverse();
    let rows = paths
        .into_iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .filter_map(|source| {
            let template = json_value(&source, "template")?;
            let to = json_value(&source, "to").unwrap_or_default();
            let url = json_value(
                &source,
                if template == "password_reset" {
                    "reset_url"
                } else {
                    "verification_url"
                },
            )
            .unwrap_or_default();
            Some(format!(
                "<tr><td>{}</td><td>{}</td><td><a href=\"{}\">Open development link</a></td></tr>",
                esc(&template),
                esc(&to),
                esc(&url)
            ))
        })
        .collect::<Vec<_>>()
        .join("");
    if rows.is_empty() {
        "<tr><td colspan=3>No development messages yet.</td></tr>".to_string()
    } else {
        rows
    }
}

fn json_value(source: &str, field: &str) -> Option<String> {
    let marker = format!("\"{}\":\"", field);
    Some(source.split_once(&marker)?.1.split_once('"')?.0.to_string())
}

fn save_route_access(
    root: &std::path::Path,
    method: &str,
    path: &str,
    access: &str,
) -> Result<(), CliError> {
    if !matches!(access, "default" | "authenticated" | "admin" | "user") {
        return Err(error(
            "route access must be default, authenticated, admin, or user",
        ));
    }
    let discovered = init::discovered_routes(root).unwrap_or_default();
    if !discovered
        .iter()
        .any(|route| route.method.eq_ignore_ascii_case(method) && route.path == path)
    {
        return Err(error("route is not part of the discovered application"));
    }
    let mut entries = route_access(root);
    entries.retain(|entry| !(entry.method.eq_ignore_ascii_case(method) && entry.path == path));
    if access != "default" {
        entries.push(RouteAccess {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            access: access.to_string(),
        });
    }
    entries.sort_by(|left, right| (&left.path, &left.method).cmp(&(&right.path, &right.method)));
    let records = entries
        .iter()
        .map(|entry| {
            format!(
                "    {{\"method\":\"{}\",\"path\":\"{}\",\"access\":\"{}\"}}",
                json_escape(&entry.method),
                json_escape(&entry.path),
                json_escape(&entry.access)
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let target = root.join(ROUTE_ACCESS_FILE);
    let temporary = target.with_extension("authboundry-tmp");
    std::fs::write(
        &temporary,
        format!("{{\n  \"routes\": [\n{}\n  ]\n}}\n", records),
    )
    .map_err(|err| error(format!("cannot save route access: {}", err)))?;
    std::fs::rename(&temporary, &target)
        .map_err(|err| error(format!("cannot activate route access: {}", err)))
}

fn route_capability(method: &str, path: &str, access: &str) -> String {
    let mut name = path
        .trim_matches('/')
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '.'
            }
        })
        .collect::<String>();
    while name.contains("..") {
        name = name.replace("..", ".");
    }
    let name = name.trim_matches('.');
    format!(
        "application.route.{}.{}.{}",
        method.to_ascii_lowercase(),
        if name.is_empty() { "root" } else { name },
        access
    )
}

fn development_route_grants(root: &std::path::Path) -> Vec<serve::Grant> {
    init::discovered_routes(root)
        .unwrap_or_default()
        .into_iter()
        .flat_map(|route| {
            [
                ("authenticated", "admin"),
                ("authenticated", "user"),
                ("admin", "admin"),
                ("user", "user"),
            ]
            .into_iter()
            .map(move |(access, role)| serve::Grant {
                capability: route_capability(&route.method, &route.path, access),
                claim: "role".to_string(),
                value: role.to_string(),
            })
        })
        .collect()
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

pub(crate) fn open_browser(url: &str) -> bool {
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
    let configured_access = route_access(root);
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
                let access = configured_access
                    .iter()
                    .find(|entry| {
                        entry.method.eq_ignore_ascii_case(&r.method) && entry.path == r.path
                    })
                    .map(|entry| entry.access.as_str())
                    .unwrap_or("default");
                let selected = |value: &str| if access == value { " selected" } else { "" };
                format!(
                    "<tr data-route data-method=\"{}\" data-path=\"{}\"><td>{} {}</td><td><select class=route-access><option value=default{}>Discovered default</option><option value=authenticated{}>Any signed-in user</option><option value=admin{}>Admin only</option><option value=user{}>User only</option></select></td><td><button class=save-route>Apply</button> <span class=route-status></span></td></tr>",
                    esc(&r.method),
                    esc(&r.path),
                    esc(&r.method),
                    esc(&r.path),
                    selected("default"),
                    selected("authenticated"),
                    selected("admin"),
                    selected("user")
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
    let development_accounts = init::development_accounts(root);
    let mail_rows = development_mail_rows(root);
    let account_rows = if development_accounts.is_empty() {
        "<tr><td colspan=3>No local development users configured.</td></tr>".to_string()
    } else {
        development_accounts
            .iter()
            .map(|account| {
                let role = account
                    .claims
                    .get("role")
                    .map(String::as_str)
                    .unwrap_or("user");
                format!(
                    "<tr><td><strong>{}</strong></td><td>{}</td><td><code>{}</code></td></tr>",
                    esc(&account.username),
                    esc(role),
                    esc(&account.password)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
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
:root{{color-scheme:dark;background:#0b0d10;color:#edf0f4;font:15px/1.5 system-ui,sans-serif}}body{{margin:0}}header{{padding:24px 32px;border-bottom:1px solid #292d35}}header b{{font-size:20px}}header span,.muted{{color:#99a1ad}}main{{max-width:920px;margin:auto;padding:36px 24px}}h1{{font-size:30px;margin:0 0 4px}}h2{{font-size:16px;margin:32px 0 12px}}.card{{background:#13171d;border:1px solid #292d35;border-radius:12px;padding:24px;margin:16px 0}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}}dt{{color:#99a1ad}}dd{{margin:4px 0;font-weight:650}}.ok{{color:#55d187}}.warn{{color:#f4bd61}}.off{{color:#99a1ad}}button{{background:#edf0f4;color:#101318;border:0;border-radius:7px;padding:10px 16px;font-weight:700;margin-right:8px;cursor:pointer}}button.secondary{{background:#292d35;color:#edf0f4}}input,select{{padding:10px;border:1px solid #3b414c;border-radius:7px;background:#0b0d10;color:#edf0f4;margin:8px 0}}input{{width:min(420px,90%)}}pre{{white-space:pre-wrap}}dialog{{background:#13171d;color:#edf0f4;border:1px solid #3b414c;border-radius:12px;width:min(620px,90vw)}}table{{width:100%;border-collapse:collapse}}td{{padding:9px;border-bottom:1px solid #292d35}}.route-status{{font-size:13px}}</style></head><body>
<header><b>AuthBoundry</b><br><span>Authority Boundary · Studio</span><nav>Overview · Application · Authority · Users · Mail · Routes · Providers · Sessions · Policies · Audit · Attachment</nav></header><main><h1>{name}</h1><p class="muted">What AuthBoundry currently knows and protects.</p><p><a href="/auth/login">Open generated login</a> · <a href="/" target="_blank">Open protected application</a></p>
<section class="card grid"><dl><dt>Authority</dt><dd class="ok">✓ Configured</dd></dl><dl><dt>Application</dt><dd class="{attach_class}">{application}</dd></dl><dl><dt>Protection</dt><dd class="{protect_class}">{protection}</dd></dl><dl><dt>Mode</dt><dd>Standalone</dd></dl></section>
{attach_callout}<h2>Topology</h2><section class="card grid"><dl><dt>Studio + runtime</dt><dd id="studio-origin"></dd></dl><dl><dt>Protected application upstream</dt><dd>{upstream}</dd></dl></section><h2>Application</h2><section class="card grid"><dl><dt>Language</dt><dd>{language}</dd></dl><dl><dt>Framework</dt><dd>{framework}</dd></dl><dl><dt>Package manager</dt><dd>{package_manager}</dd></dl><dl><dt>Entrypoint</dt><dd>{entrypoint}</dd></dl><dl><dt>Run command</dt><dd>{run_command}</dd></dl><dl><dt>Upstream</dt><dd>{upstream}</dd></dl></section>
<h2>Authority</h2><section class="card grid"><dl><dt>Providers</dt><dd>{providers}</dd></dl><dl><dt>Principals</dt><dd>Human · Service</dd></dl><dl><dt>Agents / Delegation</dt><dd>Disabled</dd></dl><dl><dt>Sessions · Policies · Audit</dt><dd>Runtime authority</dd></dl></section>
<h2>Development users</h2><section class="card"><p class="muted">Local-only accounts generated for this repository. Credentials are stored in <code>.authboundry/development.json</code> and excluded from git.</p><table><thead><tr><td>User</td><td>Role</td><td>Password</td></tr></thead><tbody>{account_rows}</tbody></table><h3>Create user</h3><form id="create-user"><label>Username<br><input name="username" required></label><label>Email<br><input name="email" type="email" placeholder="optional"></label><label>Password<br><input name="password" type="password" minlength="12" required></label><label>Role<br><select name="role"><option value="user">user</option><option value="admin">admin</option></select></label><br><button type="submit">Create user</button><span id="create-user-status" class="muted"></span></form></section>
<h2>Development mail</h2><section class="card"><p class="muted">Zero-configuration messages captured locally in <code>.authboundry/mail</code>.</p><table><thead><tr><td>Message</td><td>To</td><td>Action</td></tr></thead><tbody>{mail_rows}</tbody></table></section>
<h2>Routes and access</h2><section class="card"><p class="muted">Choose who may cross the boundary for each route. Changes use AuthBoundry's reviewed proposal pipeline and take effect immediately.</p><table>{route_rows}</table></section><h2>Contract</h2><p class="muted">{fingerprint}</p></main>
<dialog id="attach-dialog"><h2>Attach Application</h2><div id="attach-step"><p>Find a reachable application runtime. Reachability will not attach it.</p><label>Application upstream<br><input id="upstream" value="{upstream_input}" placeholder="http://127.0.0.1:3000"></label><p id="attach-status" class="muted"></p><button id="discover">Discover</button><button id="test-connection" class="secondary">Test Connection</button><button id="preview">Preview Attachment</button></div><div id="approval" hidden><h2>Attachment Preview</h2><pre id="preview-text"></pre><button id="cancel" class="secondary">Cancel</button><button id="approve">Approve Attachment</button></div></dialog>
<script>
const dialog=document.getElementById('attach-dialog'), status=document.getElementById('attach-status'), input=document.getElementById('upstream'); let proposal=null;
document.getElementById('studio-origin').textContent=location.origin;
const post=async(path,body={{}})=>{{const response=await fetch(path,{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify(body)}});const data=await response.json();if(!response.ok||data.ok===false)throw new Error(data.reason||'Request failed');return data}};
const applyChange=async(change)=>{{const proposal=await post('/_authboundry/propose',change);await post('/_authboundry/approve',{{proposal_id:proposal.proposal_id}});return post('/_authboundry/apply',{{proposal_id:proposal.proposal_id}})}};
const routeCapability=(method,path,access)=>'application.route.'+method.toLowerCase()+'.'+(path==='/'?'root':path.replace(/[^a-zA-Z0-9]+/g,'.').replace(/^\.|\.$/g,'').toLowerCase())+'.'+access;
document.getElementById('create-user').addEventListener('submit',async(event)=>{{event.preventDefault();const status=document.getElementById('create-user-status');status.textContent='Creating…';try{{await post('/_authboundry/application/users',Object.fromEntries(new FormData(event.target).entries()));status.textContent='✓ User created and active';status.className='ok';setTimeout(()=>location.reload(),500)}}catch(error){{status.textContent=error.message;status.className='warn'}}}});
document.querySelectorAll('[data-route]').forEach(row=>{{row.querySelector('.save-route').onclick=async()=>{{const status=row.querySelector('.route-status'), access=row.querySelector('.route-access').value, method=row.dataset.method, path=row.dataset.path, capability=routeCapability(method,path,access);status.textContent='Applying…';status.className='route-status muted';try{{if(access==='default'){{await applyChange({{type:'unprotect_route',method,path}})}}else{{const roles=access==='authenticated'?'admin,user':access;await applyChange({{type:'set_capability_policy',capability,policy:'development-policy',roles}});await applyChange({{type:'protect_route',method,path,capability}})}}await post('/_authboundry/application/routes/access',{{method,path,access}});status.textContent='✓ Active and saved';status.className='route-status ok'}}catch(error){{status.textContent=error.message;status.className='route-status warn'}}}}}});
document.getElementById('open-attachment')?.addEventListener('click',()=>dialog.showModal());
document.getElementById('discover').onclick=async()=>{{status.textContent='Discovering reachable runtimes…';try{{const data=await post('/_authboundry/application/discover');if(data.reachable){{input.value=data.upstream;status.textContent='✓ Application reachable';status.className='ok'}}else{{status.textContent='No running application was detected.';status.className='warn'}}}}catch(error){{status.textContent=error.message;status.className='warn'}}}};
document.getElementById('test-connection').onclick=async()=>{{status.textContent='Testing connection…';try{{const data=await post('/_authboundry/application/discover',{{upstream:input.value}});if(!data.reachable)throw new Error('Application not reachable. Start the application or change the upstream.');status.textContent='✓ Application reachable (not attached yet)';status.className='ok'}}catch(error){{status.textContent=error.message;status.className='warn'}}}};
document.getElementById('preview').onclick=async()=>{{status.textContent='Validating attachment…';try{{proposal=await post('/_authboundry/application/attachment/preview',{{upstream:input.value}});document.getElementById('preview-text').textContent=proposal.preview;document.getElementById('attach-step').hidden=true;document.getElementById('approval').hidden=false}}catch(error){{status.textContent=error.message;status.className='warn'}}}};
document.getElementById('cancel').onclick=()=>{{proposal=null;document.getElementById('approval').hidden=true;document.getElementById('attach-step').hidden=false;status.textContent='Attachment cancelled. No changes were made.'}};
document.getElementById('approve').onclick=async()=>{{try{{await post('/_authboundry/application/attachment/apply',{{proposal_id:proposal.proposal_id}});const result=await post('/_authboundry/application/attachment/test');status.textContent=result.request_forwarded?'✓ Attachment configured\n✓ Request crossed AuthBoundry\nBasic attachment verified.\nProtected-route verification unavailable until routes are discovered.':`Attachment saved, but the upstream did not respond through AuthBoundry (status ${{result.upstream_status}}).`;status.className=result.request_forwarded?'ok':'warn';setTimeout(()=>location.reload(),900)}}catch(error){{document.getElementById('approval').hidden=true;document.getElementById('attach-step').hidden=false;status.textContent='Attachment failed. No partial attachment was recorded.\n'+error.message;status.className='warn'}}}};
document.getElementById('detach')?.addEventListener('click',async()=>{{if(confirm('Detach this application?')){{await post('/_authboundry/application/attachment/detach');location.reload()}}}});
document.getElementById('test-boundary')?.addEventListener('click',async()=>{{const result=await post('/_authboundry/application/attachment/test');alert(result.request_forwarded?'Basic attachment verified. Request crossed AuthBoundry.':`Boundary request failed with upstream status ${{result.upstream_status}}.`)}});
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
        account_rows = account_rows,
        mail_rows = mail_rows,
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
        std::fs::write(root.join(".authboundry/development.json"), r#"{"tenant":"development","proxy_secret":"proxy","accounts":[{"username":"admin","password":"admin-secret","claims":"role=admin"},{"username":"user","password":"user-secret","claims":"role=user"}]}"#).unwrap();
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
        assert!(html.contains("Development users"));
        assert!(html.contains("Create user"));
        assert!(html.contains("/_authboundry/application/users"));
        assert!(html.contains("admin-secret"));
        assert!(html.contains("user-secret"));
        assert!(html.contains("<strong>admin</strong>"));
        assert!(html.contains("/_authboundry/application/routes/access"));
        assert!(!html.contains("authboundry attach --upstream"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn studio_preview_apply_and_detach_use_the_canonical_attachment_plan() {
        use std::collections::BTreeMap;
        use std::io::Write;
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
        std::thread::spawn(move || {
            for _ in 0..8 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    );
                } else {
                    break;
                }
            }
        });
        let surface =
            AuthSurface::derive(&parse_auth_block("use auth { providers = [local] }\n").unwrap());
        let binding = Arc::new(StudioApplication::new(&root, None).unwrap());
        let controller = RepositoryStudio::new(root.clone(), binding.clone(), surface);
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
        let tested = controller
            .handle(&request(
                "/_authboundry/application/attachment/test",
                "{}".to_string(),
            ))
            .unwrap();
        assert_eq!(tested.status, 200);
        let tested = String::from_utf8(tested.body).unwrap();
        assert!(tested.contains("\"ok\":true"));
        assert!(tested.contains("\"request_forwarded\":true"));
        assert!(tested.contains("\"upstream_status\":200"));
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

        // CLI and Studio may be separate processes. A CLI attachment must be
        // adopted by the already-running Studio on its next request.
        let external = init::plan_attachment(&root, &upstream).unwrap();
        init::apply_attachment(&external).unwrap();
        controller.page().unwrap();
        assert!(binding.proxy.read().unwrap().is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rendered_studio_javascript_is_valid() {
        let root =
            std::env::temp_dir().join(format!("authboundry-studio-js-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".authboundry")).unwrap();
        std::fs::write(root.join("package.json"), r#"{"name":"sample-app"}"#).unwrap();
        std::fs::write(root.join(".authboundry/adoption.json"), r#"{"application":"sample-app","mode":"standalone","authority":"configured","attachment":"none","upstream":"","routes":0}"#).unwrap();
        let config = parse_auth_block("use auth { providers = [local] }\n").unwrap();
        let html = render(&root, &AuthSurface::derive(&config));
        let script = html
            .split_once("<script>")
            .unwrap()
            .1
            .split_once("</script>")
            .unwrap()
            .0;
        let status = Command::new("node")
            .args(["-e", "new Function(process.argv[1])", script])
            .status()
            .unwrap();
        assert!(status.success(), "rendered Studio JavaScript must compile");
        let _ = std::fs::remove_dir_all(root);
    }
}
