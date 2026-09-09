use std::time::{SystemTime, UNIX_EPOCH};
use appport_auth_mesh_boundary::{AuthPortRuntime, AuthorityChange, Method};
use appport_auth_mesh_surface::AuthSurface;
use crate::http::{HttpRequest, HttpResponse, JsonValue};
use crate::control_types::{ApplicationDescription, RouteDescription, RouteProtection};

/// Handle control plane routes (_authport/*)
pub fn handle_control_route(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    path: &str,
    request: &HttpRequest,
) -> Option<HttpResponse> {
    // Parse control plane paths
    let method = request.method.as_str().to_uppercase();
    match (method.as_str(), path) {
        ("GET", "/_authport/overview") => Some(overview(runtime)),
        ("GET", "/_authport/routes") => Some(routes(runtime)),
        ("GET", "/_authport/policies") => Some(policies(runtime)),
        ("GET", "/_authport/providers") => Some(providers(runtime)),
        ("POST", "/_authport/propose") => Some(propose(runtime, request)),
        ("POST", "/_authport/apply") => Some(apply(runtime, request)),
        ("GET", "/_authport/history") => Some(history(runtime)),
        _ => None,
    }
}

fn overview(runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    let now = SystemTime::now();
    let uptime = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let desc = ApplicationDescription {
        name: "AuthPort".to_string(),
        deployment_mode: runtime.mode().as_str().to_string(),
        contract_fingerprint: runtime.contract().fingerprint(),
        surface_fingerprint: AuthSurface::derive(runtime.contract()).fingerprint(),
        started_at: now,
        uptime_seconds: uptime,
    };

    let json = desc.to_json();
    HttpResponse::ok_json(json)
}

fn routes(runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    use appport_auth_mesh_surface::AuthMethod;

    let surface = AuthSurface::derive(runtime.contract());
    let _authority = runtime.live_authority();

    let descriptions: Vec<RouteDescription> = surface
        .routes
        .iter()
        .map(|route| {
            let methods = route
                .methods
                .iter()
                .map(|m| m.as_str().to_string())
                .collect::<Vec<_>>();

            // Check if this route has live protection
            // Convert AuthMethod to Method for checking protection
            let protection = if let Some(auth_method) = route.methods.first() {
                let method = match auth_method {
                    AuthMethod::Get => Method::Get,
                    AuthMethod::Post => Method::Post,
                    AuthMethod::Delete => Method::Delete,
                };
                if let Some(cap) = runtime.get_route_protection(&method, &route.path) {
                    RouteProtection::CapabilityRequired(cap)
                } else {
                    RouteProtection::None
                }
            } else {
                RouteProtection::None
            };

            RouteDescription {
                path: route.path.clone(),
                methods,
                protection,
                aliases: route.aliases.clone(),
            }
        })
        .collect();

    let json = JsonValue::Array(descriptions.iter().map(|d| d.to_json()).collect());
    HttpResponse::ok_json(json)
}

fn policies(runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    let authority = runtime.live_authority();

    let policies_json: Vec<(String, JsonValue)> = authority
        .capability_policies
        .iter()
        .map(|(cap, policy)| {
            (
                cap.clone(),
                JsonValue::String(format!("{:?}", policy)),
            )
        })
        .collect();

    let json = JsonValue::Object(vec![
        ("revision".to_string(), JsonValue::Number(authority.revision as f64)),
        ("policies".to_string(), JsonValue::Object(policies_json)),
    ]);

    HttpResponse::ok_json(json)
}

fn providers(runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    let _authority = runtime.live_authority();

    let providers_json: Vec<JsonValue> = runtime
        .providers()
        .iter()
        .map(|provider| {
            let enabled = runtime.is_provider_enabled(&provider.id);
            JsonValue::Object(vec![
                ("id".to_string(), JsonValue::String(provider.id.clone())),
                ("kind".to_string(), JsonValue::String(provider.kind.as_str().to_string())),
                ("enabled".to_string(), JsonValue::String(if enabled { "true" } else { "false" }.to_string())),
            ])
        })
        .collect();

    let json = JsonValue::Array(providers_json);
    HttpResponse::ok_json(json)
}

fn propose(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    // Parse the request body to extract AuthorityChange
    let change = match parse_authority_change(request) {
        Ok(change) => change,
        Err(msg) => return HttpResponse::bad_request(&msg),
    };

    // Propose the change
    match runtime.propose_change(change) {
        Ok(proposal) => {
            let json = JsonValue::Object(vec![
                ("revision".to_string(), JsonValue::Number(proposal.revision as f64)),
                ("preview".to_string(), JsonValue::Object(vec![
                    ("before".to_string(), JsonValue::String("(state snapshot)".to_string())),
                    ("after".to_string(), JsonValue::String("(state snapshot)".to_string())),
                ])),
            ]);
            HttpResponse::ok_json(json)
        }
        Err(msg) => HttpResponse::bad_request(&msg),
    }
}

fn apply(_runtime: &std::sync::Arc<AuthPortRuntime>, _request: &HttpRequest) -> HttpResponse {
    // For now, return 501 Not Implemented
    // Implementing full apply requires storing proposals and handling approval tokens
    HttpResponse::not_implemented("apply endpoint requires proposal storage")
}

fn history(_runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    // For now, return empty history
    let json = JsonValue::Array(vec![]);
    HttpResponse::ok_json(json)
}

fn parse_authority_change(request: &HttpRequest) -> Result<AuthorityChange, String> {
    // Simple JSON parser for AuthorityChange
    let body_str = String::from_utf8_lossy(&request.body);

    // Very basic parsing - in production would use proper JSON parser
    if body_str.contains("protect_route") {
        // Extract fields
        let method_str = extract_quoted_field(&body_str, "method").ok_or("missing method")?;
        let method = match method_str.to_uppercase().as_str() {
            "POST" => Method::Post,
            "GET" => Method::Get,
            "PUT" => Method::Put,
            "PATCH" => Method::Patch,
            "DELETE" => Method::Delete,
            "HEAD" => Method::Head,
            "OPTIONS" => Method::Options,
            _ => return Err(format!("unknown method: {}", method_str)),
        };

        let path = extract_quoted_field(&body_str, "path").ok_or("missing path")?;
        let capability = extract_quoted_field(&body_str, "capability").ok_or("missing capability")?;

        Ok(AuthorityChange::ProtectRoute {
            method,
            path,
            capability,
        })
    } else if body_str.contains("unprotect_route") {
        let method_str = extract_quoted_field(&body_str, "method").ok_or("missing method")?;
        let method = match method_str.to_uppercase().as_str() {
            "POST" => Method::Post,
            "GET" => Method::Get,
            "PUT" => Method::Put,
            "PATCH" => Method::Patch,
            "DELETE" => Method::Delete,
            "HEAD" => Method::Head,
            "OPTIONS" => Method::Options,
            _ => return Err(format!("unknown method: {}", method_str)),
        };
        let path = extract_quoted_field(&body_str, "path").ok_or("missing path")?;

        Ok(AuthorityChange::UnprotectRoute { method, path })
    } else if body_str.contains("set_provider_enabled") {
        let provider = extract_quoted_field(&body_str, "provider").ok_or("missing provider")?;
        let enabled = body_str.contains("\"enabled\": true");

        Ok(AuthorityChange::SetProviderEnabled { provider, enabled })
    } else {
        Err("unknown action".to_string())
    }
}

fn extract_quoted_field(json: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\":", field);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];

    // Skip whitespace
    let rest = rest.trim_start();

    if rest.starts_with('"') {
        // Quoted string value
        let end = rest[1..].find('"')?;
        Some(rest[1..end + 1].to_string())
    } else {
        None
    }
}
