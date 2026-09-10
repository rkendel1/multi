use crate::control_types::{ApplicationDescription, RouteDescription, RouteProtection};
use crate::http::{HttpRequest, HttpResponse, JsonValue};
use crate::router::ApplicationBinding;
use appport_auth_mesh_authz::Policy;
use appport_auth_mesh_boundary::{
    Approval, AuthPortRuntime, AuthorityChange, ChangeRecord, Method, ProposalMetadata,
    ProposalSource, ProposalStatus, RouteId, RouteProtection as LiveRouteProtection,
    StoredProposal,
};
use appport_auth_mesh_contract::PolicyId;
use appport_auth_mesh_discovery::{
    propose_authority, render_proposal_json, ApplicationCandidate, AuthorityProposal,
    DiscoveryConfidence, ExistingAuthPort, ProposalReviewStatus, RecommendationAction,
};
use appport_auth_mesh_surface::AuthSurface;
use std::time::{SystemTime, UNIX_EPOCH};

/// Handle control plane routes (_authport/*)
pub fn handle_control_route(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    app: &dyn ApplicationBinding,
    path: &str,
    request: &HttpRequest,
) -> Option<HttpResponse> {
    // Parse control plane paths
    let method = request.method.as_str().to_uppercase();
    match (method.as_str(), path) {
        ("GET", "/_authport/overview") => Some(overview(runtime)),
        ("GET", "/_authport/routes") => Some(routes(runtime)),
        ("GET", "/_authport/authority-proposal") => Some(authority_proposal(runtime, app)),
        _ if method == "POST"
            && path.starts_with("/_authport/authority-proposal/")
            && path.ends_with("/approve") =>
        {
            Some(approve_authority_proposal(runtime, path))
        }
        _ if method == "POST"
            && path.starts_with("/_authport/authority-proposal/")
            && path.ends_with("/apply") =>
        {
            Some(apply_authority_proposal(runtime, path))
        }
        ("POST", "/_authport/authority-proposals/approve") => Some(approve_bulk(runtime, request)),
        ("POST", "/_authport/authority-proposals/apply") => Some(apply_bulk(runtime, request)),
        ("GET", "/_authport/policies") => Some(policies(runtime)),
        ("GET", "/_authport/providers") => Some(providers(runtime)),
        ("POST", "/_authport/propose") => Some(propose(runtime, request)),
        ("POST", "/_authport/approve") => Some(approve(runtime, request)),
        ("POST", "/_authport/apply") => Some(apply(runtime, request)),
        ("POST", "/_authport/reject") => Some(reject(runtime, request)),
        ("POST", "/_authport/revert") => Some(revert(runtime, request)),
        ("GET", "/_authport/history") => Some(history(runtime, request)),
        ("GET", "/_authport/proposals") => Some(proposals(runtime, request)),
        _ if method == "GET" && path.starts_with("/_authport/proposals/") => {
            Some(proposal(runtime, path))
        }
        _ => None,
    }
}

fn authority_proposal(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    app: &dyn ApplicationBinding,
) -> HttpResponse {
    let application = ApplicationCandidate {
        root: std::path::PathBuf::new(),
        name: Some("AuthPort".to_string()),
        language: None,
        framework: None,
        package_manager: None,
        entrypoints: Vec::new(),
        servers: Vec::new(),
        routes: app.observed_routes(),
        providers: Vec::new(),
        existing_authport: ExistingAuthPort::default(),
        confidence: DiscoveryConfidence::High,
    };
    let authority = runtime.live_authority();
    let existing = authority
        .route_protection
        .iter()
        .filter_map(|(route, protection)| {
            protection.capability.clone().map(|capability| {
                (
                    (route.method.as_str().to_string(), route.path.clone()),
                    capability,
                )
            })
        })
        .collect();
    let mut proposal = propose_authority(
        &application,
        runtime.contract().fingerprint(),
        authority.revision,
        &existing,
    );
    attach_inferred_proposals(runtime, &mut proposal);
    HttpResponse::json(200, render_proposal_json(&proposal))
}

fn attach_inferred_proposals(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    proposal: &mut AuthorityProposal,
) {
    let current_revision = runtime.live_authority().revision;
    for recommendation in proposal
        .recommendations
        .iter_mut()
        .filter(|item| item.action == RecommendationAction::ProtectRoute)
    {
        let method = match Method::parse(&recommendation.method) {
            Some(method) => method,
            None => continue,
        };
        let capability = match recommendation.capability.clone() {
            Some(capability) => capability,
            None => continue,
        };
        let change = AuthorityChange::ProtectRoute {
            method,
            path: recommendation.path.clone(),
            capability,
        };
        if let Ok(stored) = runtime.ensure_proposal(
            change,
            ProposalSource::Inferred,
            proposal.discovery_revision,
        ) {
            recommendation.id = Some(stored.id);
            recommendation.status = if stored.revision != current_revision {
                ProposalReviewStatus::Stale
            } else {
                match stored.status {
                    ProposalStatus::Pending => ProposalReviewStatus::Recommended,
                    ProposalStatus::Approved => ProposalReviewStatus::Approved,
                    ProposalStatus::Applied => ProposalReviewStatus::AlreadyProtected,
                    ProposalStatus::Rejected => ProposalReviewStatus::Rejected,
                }
            };
        }
    }
}

fn overview(runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    let now = SystemTime::now();
    let uptime = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

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
        .map(|(cap, policy)| (cap.clone(), JsonValue::String(format!("{:?}", policy))))
        .collect();

    let json = JsonValue::Object(vec![
        (
            "revision".to_string(),
            JsonValue::Number(authority.revision as f64),
        ),
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
                (
                    "kind".to_string(),
                    JsonValue::String(provider.kind.as_str().to_string()),
                ),
                (
                    "enabled".to_string(),
                    JsonValue::String(if enabled { "true" } else { "false" }.to_string()),
                ),
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
                (
                    "proposal_id".to_string(),
                    JsonValue::String(proposal.id.clone()),
                ),
                (
                    "revision".to_string(),
                    JsonValue::Number(proposal.revision as f64),
                ),
                ("change".to_string(), change_to_json(&proposal.change)),
                ("preview".to_string(), preview_to_json(&proposal.preview)),
                (
                    "approval_token".to_string(),
                    JsonValue::String(Approval::for_proposal(&proposal).token),
                ),
            ]);
            HttpResponse::ok_json(json)
        }
        Err(msg) => HttpResponse::bad_request(&msg),
    }
}

fn apply(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    let body_str = String::from_utf8_lossy(&request.body);
    let proposal_id = match extract_quoted_field(&body_str, "proposal_id")
        .or_else(|| extract_quoted_field(&body_str, "proposal-id"))
    {
        Some(id) => id,
        None => return HttpResponse::bad_request("missing proposal_id"),
    };
    let approval = match extract_quoted_field(&body_str, "approval_token") {
        Some(token) => Some(Approval { token }),
        None => None,
    };

    let outcome = match approval {
        Some(approval) => runtime.apply_stored_proposal(&proposal_id, approval),
        None => runtime.apply_approved_stored_proposal(&proposal_id),
    };

    match outcome {
        Ok((change_id, new_revision)) => HttpResponse::ok_json(JsonValue::Object(vec![
            (
                "applied_change_id".to_string(),
                JsonValue::String(change_id),
            ),
            (
                "new_revision".to_string(),
                JsonValue::Number(new_revision as f64),
            ),
        ])),
        Err(msg) => proposal_error(runtime, &msg),
    }
}

fn approve(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    let body_str = String::from_utf8_lossy(&request.body);
    let proposal_id = match extract_quoted_field(&body_str, "proposal_id")
        .or_else(|| extract_quoted_field(&body_str, "proposal-id"))
    {
        Some(id) => id,
        None => return HttpResponse::bad_request("missing proposal_id"),
    };
    match runtime.approve_stored_proposal(&proposal_id) {
        Ok(()) => HttpResponse::ok_json(JsonValue::Object(vec![
            ("proposal_id".to_string(), JsonValue::String(proposal_id)),
            (
                "status".to_string(),
                JsonValue::String(ProposalStatus::Approved.as_str().to_string()),
            ),
        ])),
        Err(msg) => proposal_error(runtime, &msg),
    }
}

fn reject(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    let body_str = String::from_utf8_lossy(&request.body);
    let proposal_id = match extract_quoted_field(&body_str, "proposal_id")
        .or_else(|| extract_quoted_field(&body_str, "proposal-id"))
    {
        Some(id) => id,
        None => return HttpResponse::bad_request("missing proposal_id"),
    };
    let reason =
        extract_quoted_field(&body_str, "reason").unwrap_or_else(|| "rejected".to_string());
    match runtime.reject_stored_proposal(&proposal_id, reason) {
        Ok(()) => HttpResponse::ok_json(JsonValue::Object(vec![
            ("proposal_id".to_string(), JsonValue::String(proposal_id)),
            (
                "status".to_string(),
                JsonValue::String(ProposalStatus::Rejected.as_str().to_string()),
            ),
        ])),
        Err(msg) => proposal_error(runtime, &msg),
    }
}

fn approve_authority_proposal(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    path: &str,
) -> HttpResponse {
    let proposal_id = path
        .trim_start_matches("/_authport/authority-proposal/")
        .trim_end_matches("/approve");
    match runtime.approve_stored_proposal(proposal_id) {
        Ok(()) => HttpResponse::ok_json(JsonValue::Object(vec![
            (
                "proposal_id".to_string(),
                JsonValue::String(proposal_id.to_string()),
            ),
            (
                "status".to_string(),
                JsonValue::String(ProposalStatus::Approved.as_str().to_string()),
            ),
        ])),
        Err(msg) => proposal_error(runtime, &msg),
    }
}

fn apply_authority_proposal(runtime: &std::sync::Arc<AuthPortRuntime>, path: &str) -> HttpResponse {
    let proposal_id = path
        .trim_start_matches("/_authport/authority-proposal/")
        .trim_end_matches("/apply");
    match runtime.apply_approved_stored_proposal(proposal_id) {
        Ok((change_id, new_revision)) => HttpResponse::ok_json(JsonValue::Object(vec![
            (
                "applied_change_id".to_string(),
                JsonValue::String(change_id),
            ),
            (
                "new_revision".to_string(),
                JsonValue::Number(new_revision as f64),
            ),
        ])),
        Err(msg) => proposal_error(runtime, &msg),
    }
}

fn approve_bulk(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    let body_str = String::from_utf8_lossy(&request.body);
    let ids = proposal_ids(&body_str);
    if ids.is_empty() {
        return HttpResponse::bad_request("missing proposal_ids");
    }
    let mut approved = Vec::new();
    for id in ids {
        if let Err(msg) = runtime.approve_stored_proposal(&id) {
            return proposal_error(runtime, &msg);
        }
        approved.push(JsonValue::String(id));
    }
    HttpResponse::ok_json(JsonValue::Object(vec![(
        "approved".to_string(),
        JsonValue::Array(approved),
    )]))
}

fn apply_bulk(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    let body_str = String::from_utf8_lossy(&request.body);
    let ids = proposal_ids(&body_str);
    if ids.is_empty() {
        return HttpResponse::bad_request("missing proposal_ids");
    }
    match runtime.apply_approved_stored_proposals(&ids) {
        Ok(outcomes) => HttpResponse::ok_json(JsonValue::Object(vec![(
            "applied".to_string(),
            JsonValue::Array(
                outcomes
                    .into_iter()
                    .map(|(proposal_id, change_id, new_revision)| {
                        JsonValue::Object(vec![
                            ("proposal_id".to_string(), JsonValue::String(proposal_id)),
                            (
                                "applied_change_id".to_string(),
                                JsonValue::String(change_id),
                            ),
                            (
                                "new_revision".to_string(),
                                JsonValue::Number(new_revision as f64),
                            ),
                        ])
                    })
                    .collect(),
            ),
        )])),
        Err(msg) => proposal_error(runtime, &msg),
    }
}

fn revert(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    let body_str = String::from_utf8_lossy(&request.body);
    let change_id = match extract_quoted_field(&body_str, "change_id") {
        Some(id) => id,
        None => return HttpResponse::bad_request("missing change_id"),
    };

    propose(
        runtime,
        &HttpRequest {
            body: format!(
                "{{\"type\": \"revert\", \"change_id\": \"{}\"}}",
                crate::http::escape(&change_id)
            )
            .into_bytes(),
            ..request.clone()
        },
    )
}

fn history(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    let (limit, offset) = pagination(request);
    match runtime.history(limit, offset) {
        Ok(records) => HttpResponse::ok_json(JsonValue::Array(
            records.iter().map(change_record_to_json).collect(),
        )),
        Err(msg) => HttpResponse::bad_request(&msg),
    }
}

fn proposals(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    let (limit, offset) = pagination(request);
    match runtime.list_proposals(limit, offset) {
        Ok(items) => {
            let source = request
                .query
                .get("source")
                .and_then(|value| parse_source(value));
            HttpResponse::ok_json(JsonValue::Array(
                items
                    .iter()
                    .filter(|item| source.map(|source| item.source == source).unwrap_or(true))
                    .map(proposal_metadata_to_json)
                    .collect(),
            ))
        }
        Err(msg) => HttpResponse::bad_request(&msg),
    }
}

fn proposal(runtime: &std::sync::Arc<AuthPortRuntime>, path: &str) -> HttpResponse {
    let proposal_id = path.trim_start_matches("/_authport/proposals/");
    match runtime.retrieve_proposal(proposal_id) {
        Ok(item) => HttpResponse::ok_json(stored_proposal_to_json(&item)),
        Err(msg) => HttpResponse::bad_request(&msg),
    }
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
        let capability =
            extract_quoted_field(&body_str, "capability").ok_or("missing capability")?;

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
    } else if body_str.contains("set_policy") || body_str.contains("set_capability_policy") {
        let capability =
            extract_quoted_field(&body_str, "capability").ok_or("missing capability")?;
        let policy_id = extract_quoted_field(&body_str, "policy").ok_or("missing policy")?;

        Ok(AuthorityChange::SetCapabilityPolicy {
            capability,
            policy: Policy {
                id: PolicyId(policy_id),
                rules: Vec::new(),
            },
        })
    } else if body_str.contains("set_provider_enabled")
        || body_str.contains("enable_provider")
        || body_str.contains("disable_provider")
    {
        let provider = extract_quoted_field(&body_str, "provider").ok_or("missing provider")?;
        let enabled =
            body_str.contains("\"enabled\": true") || body_str.contains("enable_provider");

        Ok(AuthorityChange::SetProviderEnabled { provider, enabled })
    } else if body_str.contains("revert") {
        let change_id = extract_quoted_field(&body_str, "change_id").ok_or("missing change_id")?;
        Ok(AuthorityChange::Revert { change_id })
    } else {
        Err("unknown action".to_string())
    }
}

fn pagination(request: &HttpRequest) -> (usize, usize) {
    let limit = request
        .query
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50);
    let offset = request
        .query
        .get("offset")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    (limit, offset)
}

fn proposal_error(runtime: &std::sync::Arc<AuthPortRuntime>, message: &str) -> HttpResponse {
    if message.starts_with("STALE_AUTHORITY_PROPOSAL") {
        return HttpResponse::json(
            400,
            JsonValue::Object(vec![
                (
                    "error".to_string(),
                    JsonValue::String("STALE_AUTHORITY_PROPOSAL".to_string()),
                ),
                (
                    "message".to_string(),
                    JsonValue::String(message.to_string()),
                ),
                (
                    "current_authority_revision".to_string(),
                    JsonValue::Number(runtime.live_authority().revision as f64),
                ),
            ])
            .to_string(),
        );
    }
    HttpResponse::bad_request(message)
}

fn parse_source(value: &str) -> Option<ProposalSource> {
    match value {
        "explicit" => Some(ProposalSource::Explicit),
        "inferred" => Some(ProposalSource::Inferred),
        "imported" => Some(ProposalSource::Imported),
        _ => None,
    }
}

fn proposal_ids(body: &str) -> Vec<String> {
    if let Some(value) = extract_quoted_field(body, "proposal_ids") {
        return value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect();
    }
    if let Some(value) = extract_quoted_field(body, "proposal_id") {
        return vec![value];
    }
    let pattern = "\"proposal_ids\"";
    let rest = match body
        .find(pattern)
        .and_then(|start| body.get(start + pattern.len()..))
    {
        Some(rest) => rest,
        None => return Vec::new(),
    };
    let array = match rest.find('[').and_then(|start| rest.get(start + 1..)) {
        Some(array) => array,
        None => return Vec::new(),
    };
    let array = array.split(']').next().unwrap_or("");
    array
        .split(',')
        .filter_map(|item| {
            let item = item.trim();
            item.strip_prefix('"')
                .and_then(|item| item.strip_suffix('"'))
                .map(str::to_string)
        })
        .collect()
}

fn proposal_status_json(status: &ProposalStatus) -> JsonValue {
    JsonValue::String(status.as_str().to_string())
}

fn system_time_json(time: SystemTime) -> JsonValue {
    JsonValue::Number(
        time.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as f64,
    )
}

fn proposal_metadata_to_json(metadata: &ProposalMetadata) -> JsonValue {
    JsonValue::Object(vec![
        ("id".to_string(), JsonValue::String(metadata.id.clone())),
        (
            "change_type".to_string(),
            JsonValue::String(metadata.change_type.clone()),
        ),
        ("status".to_string(), proposal_status_json(&metadata.status)),
        (
            "revision".to_string(),
            JsonValue::Number(metadata.revision as f64),
        ),
        (
            "source".to_string(),
            JsonValue::String(metadata.source.as_str().to_string()),
        ),
        (
            "created_at".to_string(),
            system_time_json(metadata.created_at),
        ),
        (
            "applied_at".to_string(),
            metadata
                .applied_at
                .map(system_time_json)
                .unwrap_or(JsonValue::Null),
        ),
    ])
}

fn stored_proposal_to_json(proposal: &StoredProposal) -> JsonValue {
    JsonValue::Object(vec![
        ("id".to_string(), JsonValue::String(proposal.id.clone())),
        ("change".to_string(), change_to_json(&proposal.change)),
        ("preview".to_string(), preview_to_json(&proposal.preview)),
        (
            "revision".to_string(),
            JsonValue::Number(proposal.revision as f64),
        ),
        (
            "contract_fingerprint".to_string(),
            JsonValue::String(proposal.contract_fingerprint.clone()),
        ),
        (
            "discovery_revision".to_string(),
            JsonValue::Number(proposal.discovery_revision as f64),
        ),
        (
            "source".to_string(),
            JsonValue::String(proposal.source.as_str().to_string()),
        ),
        ("status".to_string(), proposal_status_json(&proposal.status)),
        (
            "created_at".to_string(),
            system_time_json(proposal.created_at),
        ),
        (
            "applied_at".to_string(),
            proposal
                .applied_at
                .map(system_time_json)
                .unwrap_or(JsonValue::Null),
        ),
        (
            "change_id".to_string(),
            proposal
                .change_id
                .clone()
                .map(JsonValue::String)
                .unwrap_or(JsonValue::Null),
        ),
        (
            "rejection_reason".to_string(),
            proposal
                .rejection_reason
                .clone()
                .map(JsonValue::String)
                .unwrap_or(JsonValue::Null),
        ),
    ])
}

fn change_record_to_json(record: &ChangeRecord) -> JsonValue {
    JsonValue::Object(vec![
        (
            "change_id".to_string(),
            JsonValue::String(record.change_id.clone()),
        ),
        (
            "proposal_id".to_string(),
            JsonValue::String(record.proposal_id.clone()),
        ),
        (
            "change_type".to_string(),
            JsonValue::String(record.change.change_type().to_string()),
        ),
        ("change".to_string(), change_to_json(&record.change)),
        (
            "applied_at".to_string(),
            system_time_json(record.applied_at),
        ),
        (
            "applied_by".to_string(),
            record
                .applied_by
                .clone()
                .map(JsonValue::String)
                .unwrap_or(JsonValue::Null),
        ),
        (
            "reverted_change_id".to_string(),
            record
                .reverted_change_id
                .clone()
                .map(JsonValue::String)
                .unwrap_or(JsonValue::Null),
        ),
        (
            "previous_revision".to_string(),
            JsonValue::Number(record.previous_state.revision as f64),
        ),
        (
            "resulting_revision".to_string(),
            JsonValue::Number(record.resulting_state.revision as f64),
        ),
    ])
}

fn preview_to_json(preview: &appport_auth_mesh_boundary::Preview) -> JsonValue {
    JsonValue::Object(vec![
        ("before".to_string(), preview_state_to_json(&preview.before)),
        ("after".to_string(), preview_state_to_json(&preview.after)),
    ])
}

fn preview_state_to_json(state: &appport_auth_mesh_boundary::control::PreviewState) -> JsonValue {
    JsonValue::Object(vec![
        (
            "route_protection".to_string(),
            route_protection_map_to_json(&state.route_protection),
        ),
        (
            "capability_policies".to_string(),
            JsonValue::Object(
                state
                    .capability_policies
                    .iter()
                    .map(|(capability, policy)| {
                        (capability.clone(), JsonValue::String(policy.id.0.clone()))
                    })
                    .collect(),
            ),
        ),
        (
            "provider_state".to_string(),
            JsonValue::Object(
                state
                    .provider_state
                    .iter()
                    .map(|(provider, state)| (provider.clone(), JsonValue::Bool(state.enabled)))
                    .collect(),
            ),
        ),
    ])
}

fn route_protection_map_to_json(
    routes: &std::collections::BTreeMap<RouteId, LiveRouteProtection>,
) -> JsonValue {
    JsonValue::Array(
        routes
            .iter()
            .map(|(route, protection)| {
                JsonValue::Object(vec![
                    (
                        "method".to_string(),
                        JsonValue::String(route.method.as_str().to_string()),
                    ),
                    ("path".to_string(), JsonValue::String(route.path.clone())),
                    (
                        "capability".to_string(),
                        protection
                            .capability
                            .clone()
                            .map(JsonValue::String)
                            .unwrap_or(JsonValue::Null),
                    ),
                ])
            })
            .collect(),
    )
}

fn change_to_json(change: &AuthorityChange) -> JsonValue {
    match change {
        AuthorityChange::ProtectRoute {
            method,
            path,
            capability,
        } => JsonValue::Object(vec![
            (
                "type".to_string(),
                JsonValue::String("protect_route".to_string()),
            ),
            (
                "method".to_string(),
                JsonValue::String(method.as_str().to_string()),
            ),
            ("path".to_string(), JsonValue::String(path.clone())),
            (
                "capability".to_string(),
                JsonValue::String(capability.clone()),
            ),
        ]),
        AuthorityChange::UnprotectRoute { method, path } => JsonValue::Object(vec![
            (
                "type".to_string(),
                JsonValue::String("unprotect_route".to_string()),
            ),
            (
                "method".to_string(),
                JsonValue::String(method.as_str().to_string()),
            ),
            ("path".to_string(), JsonValue::String(path.clone())),
        ]),
        AuthorityChange::SetCapabilityPolicy { capability, policy } => JsonValue::Object(vec![
            (
                "type".to_string(),
                JsonValue::String("set_capability_policy".to_string()),
            ),
            (
                "capability".to_string(),
                JsonValue::String(capability.clone()),
            ),
            ("policy".to_string(), JsonValue::String(policy.id.0.clone())),
        ]),
        AuthorityChange::SetProviderEnabled { provider, enabled } => JsonValue::Object(vec![
            (
                "type".to_string(),
                JsonValue::String("set_provider_enabled".to_string()),
            ),
            ("provider".to_string(), JsonValue::String(provider.clone())),
            ("enabled".to_string(), JsonValue::Bool(*enabled)),
        ]),
        AuthorityChange::Revert { change_id } => JsonValue::Object(vec![
            ("type".to_string(), JsonValue::String("revert".to_string())),
            (
                "change_id".to_string(),
                JsonValue::String(change_id.clone()),
            ),
        ]),
    }
}

fn extract_quoted_field(json: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\":", field);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];

    // Skip whitespace
    let rest = rest.trim_start();

    if let Some(rest) = rest.strip_prefix('"') {
        // Quoted string value
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    } else {
        None
    }
}
