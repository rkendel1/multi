use crate::control_types::{ApplicationDescription, RouteDescription, RouteProtection};
use crate::http::{HttpRequest, HttpResponse, JsonValue};
use crate::router::ApplicationBinding;
use appport_auth_mesh_authz::{AuthorizationEvidence, ConditionEvidence, Policy};
use appport_auth_mesh_boundary::{
    Approval, AuthPortRuntime, AuthorityChange, ChangeRecord, Method, ProposalMetadata,
    ProposalSource, ProposalStatus, RouteId, RouteProtection as LiveRouteProtection,
    StoredProposal,
};
use appport_auth_mesh_contract::{
    AgentRun, AgentState, Capability, ClaimValue, Claims, ContractVersion, DelegationId, PolicyId,
    Principal, PrincipalId, PrincipalKind, ResourceScope, RunId, TaskId,
};
use appport_auth_mesh_discovery::{
    propose_authority, render_drift_json, render_proposal_json, render_reconciliation_json,
    ApplicationCandidate, AuthorityProposal, AuthorityReconciler, DiscoveryConfidence,
    ExistingAuthPort, ProposalHistoryItem, ProposalReviewStatus, RecommendationAction,
    ReconciliationResult,
};
use appport_auth_mesh_dsl::PasswordPolicy;
use appport_auth_mesh_runtime::{DelegationRequest, RunCreationRequest};
use appport_auth_mesh_storage::{
    export_json_lines, AuditEvent, StorageCapability, StoreDescriptor, StoreRole,
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
        ("GET", "/_authport/authority-reconciliation") => {
            Some(authority_reconciliation(runtime, app))
        }
        ("POST", "/_authport/authority-reconciliation/run") => {
            Some(authority_reconciliation(runtime, app))
        }
        ("GET", "/_authport/authority-drift") => Some(authority_drift(runtime, app)),
        ("GET", "/_authport/password-policy") => {
            Some(HttpResponse::ok_json(password_policy_json(runtime)))
        }
        ("GET", "/_authport/storage") => Some(storage(runtime)),
        ("GET", "/_authport/storage/capabilities") => Some(storage_capabilities(runtime)),
        ("GET", "/_authport/audit") => Some(audit_config(runtime)),
        ("GET", "/_authport/audit/events") => Some(audit_events(runtime, request)),
        ("GET", "/_authport/audit/export") => Some(audit_export(runtime, request)),
        ("GET", "/_authport/reporting") => Some(reporting(runtime)),
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
        _ if method == "GET" && path.starts_with("/_authport/policies/") => {
            Some(policy(runtime, path))
        }
        ("GET", "/_authport/authorization/decisions") => Some(authorization_decisions(runtime)),
        ("GET", "/_authport/authorization/explain") => Some(authorization_explain(runtime)),
        _ if method == "GET"
            && path.starts_with("/_authport/authorization/decisions/")
            && path.ends_with("/explain") =>
        {
            Some(authorization_decision_explain(runtime, path))
        }
        _ if method == "GET" && path.starts_with("/_authport/authorization/decisions/") => {
            Some(authorization_decision(runtime, path))
        }
        ("GET", "/_authport/providers") => Some(providers(runtime)),
        ("GET", "/_authport/agents") => Some(agents(runtime, request)),
        ("POST", "/_authport/agents") => Some(create_agent(runtime, request)),
        _ if method == "GET"
            && path.starts_with("/_authport/agents/")
            && path.ends_with("/runs") =>
        {
            Some(agent_runs(runtime, path, request))
        }
        _ if method == "POST"
            && path.starts_with("/_authport/agents/")
            && path.ends_with("/runs") =>
        {
            Some(create_agent_run(runtime, path, request))
        }
        _ if method == "GET" && path.starts_with("/_authport/runs/") => {
            Some(agent_run(runtime, path, request))
        }
        _ if method == "POST"
            && path.starts_with("/_authport/runs/")
            && path.ends_with("/cancel") =>
        {
            Some(cancel_agent_run(runtime, path, request))
        }
        _ if method == "GET" && path.starts_with("/_authport/agents/") => {
            Some(agent(runtime, path, request))
        }
        _ if method == "POST"
            && path.starts_with("/_authport/agents/")
            && path.ends_with("/suspend") =>
        {
            Some(set_agent_state(
                runtime,
                path,
                request,
                AgentState::Suspended,
            ))
        }
        _ if method == "POST"
            && path.starts_with("/_authport/agents/")
            && path.ends_with("/revoke") =>
        {
            Some(set_agent_state(runtime, path, request, AgentState::Revoked))
        }
        _ if method == "POST"
            && path.starts_with("/_authport/agents/")
            && path.ends_with("/retire") =>
        {
            Some(set_agent_state(runtime, path, request, AgentState::Retired))
        }
        ("GET", "/_authport/delegations") => Some(delegations(runtime, request)),
        ("POST", "/_authport/delegations") => Some(create_delegation(runtime, request)),
        _ if method == "GET" && path.starts_with("/_authport/delegations/") => {
            Some(delegation(runtime, path, request))
        }
        _ if method == "POST"
            && path.starts_with("/_authport/delegations/")
            && path.ends_with("/revoke") =>
        {
            Some(revoke_delegation(runtime, path, request))
        }
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
        name: Some("AuthBoundry".to_string()),
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

fn authority_reconciliation(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    app: &dyn ApplicationBinding,
) -> HttpResponse {
    match reconciliation_result(runtime, app) {
        Ok(result) => HttpResponse::json(200, render_reconciliation_json(&result)),
        Err(msg) => HttpResponse::bad_request(&msg),
    }
}

fn authority_drift(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    app: &dyn ApplicationBinding,
) -> HttpResponse {
    match reconciliation_result(runtime, app) {
        Ok(result) => HttpResponse::json(200, render_drift_json(&result)),
        Err(msg) => HttpResponse::bad_request(&msg),
    }
}

fn reconciliation_result(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    app: &dyn ApplicationBinding,
) -> Result<ReconciliationResult, String> {
    let application = live_application(app);
    let authority = runtime.live_authority();
    let existing = authority_mappings(&authority);
    let history = proposal_history(runtime)?;
    let mut result = AuthorityReconciler::reconcile(
        None,
        &application,
        runtime.contract().fingerprint(),
        authority.revision,
        &existing,
        &history,
    );
    attach_reconciliation_proposals(runtime, &mut result);
    Ok(result)
}

fn live_application(app: &dyn ApplicationBinding) -> ApplicationCandidate {
    ApplicationCandidate {
        root: std::path::PathBuf::new(),
        name: Some("AuthBoundry".to_string()),
        language: None,
        framework: None,
        package_manager: None,
        entrypoints: Vec::new(),
        servers: Vec::new(),
        routes: app.observed_routes(),
        providers: Vec::new(),
        existing_authport: ExistingAuthPort::default(),
        confidence: DiscoveryConfidence::High,
    }
}

fn authority_mappings(
    authority: &appport_auth_mesh_boundary::LiveAuthorityState,
) -> std::collections::BTreeMap<(String, String), String> {
    authority
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
        .collect()
}

fn proposal_history(
    runtime: &std::sync::Arc<AuthPortRuntime>,
) -> Result<Vec<ProposalHistoryItem>, String> {
    Ok(runtime
        .list_proposals(1_000, 0)?
        .into_iter()
        .filter_map(|metadata| runtime.retrieve_proposal(&metadata.id).ok())
        .filter_map(|proposal| match proposal.change {
            AuthorityChange::ProtectRoute {
                method,
                path,
                capability,
            } => Some(ProposalHistoryItem {
                id: proposal.id,
                method: method.as_str().to_string(),
                path,
                capability,
                status: proposal.status.as_str().to_string(),
                discovery_revision: proposal.discovery_revision,
                authority_revision: proposal.revision,
            }),
            _ => None,
        })
        .collect::<Vec<_>>())
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
                    ProposalStatus::Active => ProposalReviewStatus::Recommended,
                    ProposalStatus::Orphaned
                    | ProposalStatus::Stale
                    | ProposalStatus::Superseded => ProposalReviewStatus::Stale,
                }
            };
        }
    }
}

fn attach_reconciliation_proposals(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    result: &mut ReconciliationResult,
) {
    let current_revision = runtime.live_authority().revision;
    for recommendation in &mut result.new_authority_proposals {
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
        if let Ok(stored) =
            runtime.ensure_proposal(change, ProposalSource::Inferred, result.discovery_revision)
        {
            recommendation.id = Some(stored.id);
            recommendation.status = if stored.revision != current_revision {
                ProposalReviewStatus::Stale
            } else {
                match stored.status {
                    ProposalStatus::Pending => ProposalReviewStatus::Recommended,
                    ProposalStatus::Approved => ProposalReviewStatus::Approved,
                    ProposalStatus::Applied => ProposalReviewStatus::AlreadyProtected,
                    ProposalStatus::Rejected => ProposalReviewStatus::Rejected,
                    ProposalStatus::Active => ProposalReviewStatus::Recommended,
                    ProposalStatus::Orphaned
                    | ProposalStatus::Stale
                    | ProposalStatus::Superseded => ProposalReviewStatus::Stale,
                }
            };
        }
    }
}

fn overview(runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    let now = SystemTime::now();
    let uptime = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    let desc = ApplicationDescription {
        name: "AuthBoundry".to_string(),
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

fn storage(runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    let topology = runtime.storage_topology();
    HttpResponse::ok_json(JsonValue::Object(vec![
        (
            "boundary".to_string(),
            JsonValue::String("storage_adapter_contract".to_string()),
        ),
        (
            "authority_store".to_string(),
            JsonValue::String(runtime.contract().storage.authority.clone()),
        ),
        (
            "audit_store".to_string(),
            JsonValue::String(runtime.contract().storage.audit.clone()),
        ),
        (
            "reporting_store".to_string(),
            JsonValue::String(runtime.contract().storage.reporting.clone()),
        ),
        (
            "stores".to_string(),
            JsonValue::Array(topology.stores.iter().map(store_descriptor_json).collect()),
        ),
    ]))
}

fn storage_capabilities(runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    HttpResponse::ok_json(JsonValue::Object(vec![(
        "capabilities".to_string(),
        JsonValue::Array(
            runtime
                .storage_topology()
                .stores
                .iter()
                .map(store_descriptor_json)
                .collect(),
        ),
    )]))
}

fn audit_config(runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    HttpResponse::ok_json(JsonValue::Object(vec![
        (
            "canonical_event".to_string(),
            JsonValue::String("authport.audit/v1".to_string()),
        ),
        (
            "durable_store".to_string(),
            JsonValue::String(runtime.contract().storage.audit.clone()),
        ),
        ("sink_is_authoritative".to_string(), JsonValue::Bool(false)),
        (
            "required_event_failures".to_string(),
            JsonValue::String("fail_closed".to_string()),
        ),
    ]))
}

fn audit_events(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    let tenant = match tenant_from_request(runtime, request) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let since = request_value(request, "since").and_then(|value| value.parse::<i64>().ok());
    let limit = request_value(request, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100);
    match runtime.audit_events(&tenant, since, limit) {
        Ok(events) => HttpResponse::ok_json(JsonValue::Object(vec![(
            "events".to_string(),
            JsonValue::Array(events.iter().map(audit_event_json).collect()),
        )])),
        Err(err) => HttpResponse::denied(
            crate::server::status_for(&err.denial),
            err.denial.as_str(),
            &err.message,
        ),
    }
}

fn audit_export(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    let tenant = match tenant_from_request(runtime, request) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let since = request_value(request, "since").and_then(|value| value.parse::<i64>().ok());
    let limit = request_value(request, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1000);
    match runtime.audit_events(&tenant, since, limit) {
        Ok(events) => HttpResponse::new(
            200,
            "application/x-ndjson; charset=utf-8",
            export_json_lines(&events),
        ),
        Err(err) => HttpResponse::denied(
            crate::server::status_for(&err.denial),
            err.denial.as_str(),
            &err.message,
        ),
    }
}

fn reporting(runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    HttpResponse::ok_json(JsonValue::Object(vec![
        (
            "source".to_string(),
            JsonValue::String("canonical_audit_events".to_string()),
        ),
        (
            "store".to_string(),
            JsonValue::String(runtime.contract().storage.reporting.clone()),
        ),
        ("authoritative".to_string(), JsonValue::Bool(false)),
        (
            "projections".to_string(),
            JsonValue::Array(
                [
                    "authentication_activity",
                    "authorization_activity",
                    "administrative_changes",
                    "provider_usage",
                    "failed_authentication",
                    "denied_authorization",
                    "agent_activity",
                    "delegation_history",
                    "revocation_activity",
                    "tenant_activity",
                ]
                .iter()
                .map(|value| JsonValue::String((*value).to_string()))
                .collect(),
            ),
        ),
    ]))
}

fn store_descriptor_json(store: &StoreDescriptor) -> JsonValue {
    JsonValue::Object(vec![
        (
            "class".to_string(),
            JsonValue::String(store.class.as_str().to_string()),
        ),
        (
            "provider".to_string(),
            JsonValue::String(store.provider.clone()),
        ),
        (
            "role".to_string(),
            JsonValue::String(store.role.as_str().to_string()),
        ),
        (
            "authoritative".to_string(),
            JsonValue::Bool(matches!(
                store.role,
                StoreRole::Authority | StoreRole::Audit
            )),
        ),
        (
            "capabilities".to_string(),
            JsonValue::Array(
                store
                    .capabilities
                    .iter()
                    .map(storage_capability_json)
                    .collect(),
            ),
        ),
    ])
}

fn storage_capability_json(capability: &StorageCapability) -> JsonValue {
    JsonValue::String(capability.as_str().to_string())
}

fn audit_event_json(event: &AuditEvent) -> JsonValue {
    let mut metadata = event.metadata.iter().collect::<Vec<_>>();
    metadata.sort_by(|a, b| a.0.cmp(b.0));
    JsonValue::Object(vec![
        (
            "id".to_string(),
            JsonValue::String(event.event_id.to_string()),
        ),
        (
            "timestamp".to_string(),
            JsonValue::Number(event.timestamp as f64),
        ),
        (
            "tenant".to_string(),
            JsonValue::String(event.tenant_id.to_string()),
        ),
        (
            "principal".to_string(),
            optional_id_json(event.principal_id.as_ref().map(|id| id.as_str())),
        ),
        (
            "delegator".to_string(),
            optional_id_json(event.delegator_id.as_ref().map(|id| id.as_str())),
        ),
        (
            "session_id".to_string(),
            optional_id_json(event.session_id.as_ref().map(|id| id.as_str())),
        ),
        (
            "delegation_id".to_string(),
            optional_id_json(event.delegation_id.as_ref().map(|id| id.as_str())),
        ),
        (
            "run_id".to_string(),
            optional_id_json(event.run_id.as_ref().map(|id| id.as_str())),
        ),
        (
            "kind".to_string(),
            JsonValue::String(event.kind.as_str().to_string()),
        ),
        (
            "action".to_string(),
            optional_id_json(event.action.as_deref()),
        ),
        (
            "resource".to_string(),
            optional_id_json(event.resource.as_deref()),
        ),
        (
            "decision".to_string(),
            optional_id_json(event.decision.as_deref()),
        ),
        (
            "reason".to_string(),
            optional_id_json(event.reason.as_deref()),
        ),
        (
            "authority_revision".to_string(),
            event
                .authority_revision
                .map(|revision| JsonValue::Number(revision as f64))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "contract_fingerprint".to_string(),
            optional_id_json(event.contract_fingerprint.as_deref()),
        ),
        (
            "durability".to_string(),
            JsonValue::String(event.durability.as_str().to_string()),
        ),
        (
            "metadata".to_string(),
            JsonValue::Object(
                metadata
                    .into_iter()
                    .map(|(key, value)| (key.clone(), JsonValue::String(value.clone())))
                    .collect(),
            ),
        ),
    ])
}

fn optional_id_json(value: Option<&str>) -> JsonValue {
    value
        .map(|value| JsonValue::String(value.to_string()))
        .unwrap_or(JsonValue::Null)
}

fn policies(runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    let authority = runtime.live_authority();

    let live_policies: Vec<JsonValue> = authority
        .capability_policies
        .iter()
        .map(|(capability, policy)| policy_summary_json(capability, policy))
        .collect();
    let contract_policies = runtime
        .contract()
        .policies
        .iter()
        .map(|policy| {
            JsonValue::Object(vec![
                (
                    "id".to_string(),
                    JsonValue::String(policy.capability.clone()),
                ),
                (
                    "capability".to_string(),
                    JsonValue::String(policy.capability.clone()),
                ),
                (
                    "tenant".to_string(),
                    JsonValue::String(if policy.tenant_current {
                        "current".to_string()
                    } else {
                        "unspecified".to_string()
                    }),
                ),
                (
                    "resource".to_string(),
                    policy
                        .resource
                        .as_ref()
                        .map(|resource| JsonValue::String(resource.clone()))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "action".to_string(),
                    policy
                        .action
                        .as_ref()
                        .map(|action| JsonValue::String(action.clone()))
                        .unwrap_or(JsonValue::Null),
                ),
            ])
        })
        .collect::<Vec<_>>();

    let json = JsonValue::Object(vec![
        (
            "revision".to_string(),
            JsonValue::Number(authority.revision as f64),
        ),
        ("live_policies".to_string(), JsonValue::Array(live_policies)),
        (
            "contract_policies".to_string(),
            JsonValue::Array(contract_policies),
        ),
    ]);

    HttpResponse::ok_json(json)
}

pub fn password_policy_json(runtime: &std::sync::Arc<AuthPortRuntime>) -> JsonValue {
    let effective = runtime.effective_password_policy();
    let policy = effective.policy;
    JsonValue::Object(vec![
        (
            "min_length".to_string(),
            JsonValue::Number(policy.min_length as f64),
        ),
        (
            "max_length".to_string(),
            JsonValue::Number(policy.max_length as f64),
        ),
        (
            "require_uppercase".to_string(),
            JsonValue::Bool(policy.require_uppercase),
        ),
        (
            "require_lowercase".to_string(),
            JsonValue::Bool(policy.require_lowercase),
        ),
        (
            "require_number".to_string(),
            JsonValue::Bool(policy.require_number),
        ),
        (
            "require_special_character".to_string(),
            JsonValue::Bool(policy.require_special_character),
        ),
        (
            "expiration_days".to_string(),
            policy
                .password_expiration_days
                .map(|days| JsonValue::Number(days as f64))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "history_count".to_string(),
            JsonValue::Number(policy.password_history_count as f64),
        ),
        (
            "allow_password_change".to_string(),
            JsonValue::Bool(policy.allow_password_change),
        ),
        (
            "allow_password_reset".to_string(),
            JsonValue::Bool(policy.allow_password_reset),
        ),
        (
            "authority_revision".to_string(),
            JsonValue::Number(effective.authority_revision as f64),
        ),
        (
            "contract_fingerprint".to_string(),
            JsonValue::String(effective.contract_fingerprint),
        ),
        (
            "policy_revision".to_string(),
            JsonValue::Number(effective.policy_revision as f64),
        ),
    ])
}

fn policy(runtime: &std::sync::Arc<AuthPortRuntime>, path: &str) -> HttpResponse {
    let id = path.trim_start_matches("/_authport/policies/");
    let authority = runtime.live_authority();
    if let Some((capability, policy)) = authority
        .capability_policies
        .iter()
        .find(|(capability, policy)| capability.as_str() == id || policy.id.as_str() == id)
    {
        return HttpResponse::ok_json(policy_summary_json(capability, policy));
    }
    if let Some(policy) = runtime
        .contract()
        .policies
        .iter()
        .find(|policy| policy.capability == id)
    {
        return HttpResponse::ok_json(JsonValue::Object(vec![
            (
                "id".to_string(),
                JsonValue::String(policy.capability.clone()),
            ),
            (
                "capability".to_string(),
                JsonValue::String(policy.capability.clone()),
            ),
            (
                "tenant".to_string(),
                JsonValue::String(if policy.tenant_current {
                    "current".to_string()
                } else {
                    "unspecified".to_string()
                }),
            ),
        ]));
    }
    HttpResponse::denied(404, "policy_not_found", "no such policy")
}

fn authorization_decisions(runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    HttpResponse::ok_json(JsonValue::Object(vec![(
        "decisions".to_string(),
        JsonValue::Array(
            runtime
                .mesh()
                .recent_decisions()
                .iter()
                .map(decision_json)
                .collect(),
        ),
    )]))
}

fn authorization_explain(runtime: &std::sync::Arc<AuthPortRuntime>) -> HttpResponse {
    let decisions = runtime.mesh().recent_decisions();
    let latest = decisions
        .last()
        .map(decision_json)
        .unwrap_or(JsonValue::Null);
    HttpResponse::ok_json(JsonValue::Object(vec![
        ("latest_decision".to_string(), latest),
        (
            "message".to_string(),
            JsonValue::String(
                "authorization explanations are derived from structured decisions".to_string(),
            ),
        ),
    ]))
}

fn authorization_decision(runtime: &std::sync::Arc<AuthPortRuntime>, path: &str) -> HttpResponse {
    let id = path.trim_start_matches("/_authport/authorization/decisions/");
    match runtime
        .mesh()
        .recent_decisions()
        .iter()
        .find(|decision| decision.decision_id == id)
    {
        Some(decision) => HttpResponse::ok_json(decision_json(decision)),
        None => HttpResponse::denied(404, "decision_not_found", "no such authorization decision"),
    }
}

fn authorization_decision_explain(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    path: &str,
) -> HttpResponse {
    let id = path
        .trim_start_matches("/_authport/authorization/decisions/")
        .trim_end_matches("/explain")
        .trim_end_matches('/');
    match runtime
        .mesh()
        .recent_decisions()
        .iter()
        .find(|decision| decision.decision_id == id)
    {
        Some(decision) => HttpResponse::ok_json(decision_json(decision)),
        None => HttpResponse::denied(404, "decision_not_found", "no such authorization decision"),
    }
}

fn policy_summary_json(capability: &str, policy: &Policy) -> JsonValue {
    JsonValue::Object(vec![
        ("id".to_string(), JsonValue::String(policy.id.0.clone())),
        (
            "capability".to_string(),
            JsonValue::String(capability.to_string()),
        ),
        (
            "rules".to_string(),
            JsonValue::Array(
                policy
                    .rules
                    .iter()
                    .map(|rule| {
                        JsonValue::Object(vec![
                            (
                                "capability".to_string(),
                                JsonValue::String(rule.capability.to_string()),
                            ),
                            (
                                "effect".to_string(),
                                JsonValue::String(
                                    match rule.effect {
                                        appport_auth_mesh_authz::Effect::Allow => "allow",
                                        appport_auth_mesh_authz::Effect::Deny => "deny",
                                    }
                                    .to_string(),
                                ),
                            ),
                            (
                                "resource".to_string(),
                                rule.resource
                                    .as_ref()
                                    .map(|resource| {
                                        JsonValue::String(resource.resource_type.clone())
                                    })
                                    .unwrap_or(JsonValue::Null),
                            ),
                            (
                                "action".to_string(),
                                rule.action
                                    .as_ref()
                                    .map(|action| JsonValue::String(action.to_string()))
                                    .unwrap_or(JsonValue::Null),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn decision_json(decision: &AuthorizationEvidence) -> JsonValue {
    JsonValue::Object(vec![
        (
            "decision_id".to_string(),
            JsonValue::String(decision.decision_id.clone()),
        ),
        (
            "timestamp".to_string(),
            JsonValue::Number(decision.timestamp as f64),
        ),
        (
            "decision".to_string(),
            JsonValue::String(decision.decision.as_str().to_string()),
        ),
        (
            "allowed".to_string(),
            JsonValue::Bool(decision.decision.as_str() == "allow"),
        ),
        (
            "reason".to_string(),
            JsonValue::String(decision.reason.as_str().to_string()),
        ),
        (
            "principal".to_string(),
            JsonValue::String(decision.principal.to_string()),
        ),
        (
            "tenant".to_string(),
            JsonValue::String(decision.tenant.to_string()),
        ),
        (
            "capability".to_string(),
            JsonValue::String(decision.capability.to_string()),
        ),
        (
            "resource".to_string(),
            decision
                .resource
                .as_ref()
                .map(|resource| JsonValue::String(resource.opaque()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "action".to_string(),
            decision
                .action
                .as_ref()
                .map(|action| JsonValue::String(action.to_string()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "policy_id".to_string(),
            decision
                .policy_id
                .as_ref()
                .map(|id| JsonValue::String(id.to_string()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "matched_rules".to_string(),
            JsonValue::Array(
                decision
                    .matched_rules
                    .iter()
                    .map(|rule| JsonValue::String(rule.clone()))
                    .collect(),
            ),
        ),
        (
            "conditions".to_string(),
            JsonValue::Array(decision.conditions.iter().map(condition_json).collect()),
        ),
        (
            "authority".to_string(),
            decision
                .authority
                .as_ref()
                .map(|authority| JsonValue::String(authority.as_str().to_string()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "source".to_string(),
            JsonValue::String(
                decision
                    .authority
                    .as_ref()
                    .map(|authority| match authority.as_str() {
                        "delegated" => "delegation",
                        _ => "policy",
                    })
                    .unwrap_or("policy")
                    .to_string(),
            ),
        ),
        (
            "authority_source".to_string(),
            authority_source_json(decision),
        ),
        (
            "delegation_chain".to_string(),
            JsonValue::Array(
                decision
                    .delegation_chain
                    .iter()
                    .map(|id| JsonValue::String(id.to_string()))
                    .collect(),
            ),
        ),
        (
            "run_id".to_string(),
            decision
                .run_id
                .as_ref()
                .map(|id| JsonValue::String(id.to_string()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "task_id".to_string(),
            decision
                .task_id
                .as_ref()
                .map(|id| JsonValue::String(id.to_string()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "agent_principal".to_string(),
            decision
                .agent_principal
                .as_ref()
                .map(|id| JsonValue::String(id.to_string()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "delegation_id".to_string(),
            decision
                .delegation_id
                .as_ref()
                .map(|id| JsonValue::String(id.to_string()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "parent_run_id".to_string(),
            decision
                .parent_run_id
                .as_ref()
                .map(|id| JsonValue::String(id.to_string()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "execution_scope".to_string(),
            decision
                .execution_scope
                .as_ref()
                .map(resource_scope_json)
                .unwrap_or(JsonValue::Null),
        ),
        (
            "authority_revision".to_string(),
            JsonValue::Number(decision.authority_revision as f64),
        ),
        (
            "contract_fingerprint".to_string(),
            JsonValue::String(decision.contract_fingerprint.clone()),
        ),
        (
            "audit_event_id".to_string(),
            decision
                .audit_event_id
                .as_ref()
                .map(|id| JsonValue::String(id.to_string()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "summary".to_string(),
            JsonValue::String(decision_summary(decision)),
        ),
    ])
}

fn authority_source_json(decision: &AuthorizationEvidence) -> JsonValue {
    match (
        decision
            .authority
            .as_ref()
            .map(|authority| authority.as_str()),
        decision.delegation_chain.last(),
    ) {
        (Some("delegated"), Some(delegation_id)) => JsonValue::Object(vec![
            (
                "type".to_string(),
                JsonValue::String("delegation".to_string()),
            ),
            (
                "id".to_string(),
                JsonValue::String(delegation_id.to_string()),
            ),
            (
                "delegator".to_string(),
                decision
                    .delegated_by
                    .as_ref()
                    .map(|delegator| JsonValue::String(delegator.to_string()))
                    .unwrap_or(JsonValue::Null),
            ),
        ]),
        (Some(_), _) => JsonValue::Object(vec![(
            "type".to_string(),
            JsonValue::String("policy".to_string()),
        )]),
        _ => JsonValue::Null,
    }
}

fn condition_json(condition: &ConditionEvidence) -> JsonValue {
    JsonValue::Object(vec![
        (
            "condition".to_string(),
            JsonValue::String(condition.condition.clone()),
        ),
        (
            "result".to_string(),
            JsonValue::String(condition.result.as_str().to_string()),
        ),
        (
            "fact".to_string(),
            condition
                .fact
                .as_ref()
                .map(|fact| JsonValue::String(fact.clone()))
                .unwrap_or(JsonValue::Null),
        ),
    ])
}

fn decision_summary(decision: &AuthorizationEvidence) -> String {
    let resource = decision
        .resource
        .as_ref()
        .map(|resource| resource.opaque())
        .unwrap_or_else(|| "no resource".to_string());
    format!(
        "{} {} {} for {} on {} because {}",
        decision.capability,
        decision
            .action
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "use".to_string()),
        decision.decision.as_str(),
        decision.principal,
        resource,
        decision.reason.as_str()
    )
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

fn agents(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    let tenant = match tenant_from_request(runtime, request) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let agents = runtime
        .mesh()
        .stores()
        .principals
        .list_principals(&tenant)
        .unwrap_or_default()
        .into_iter()
        .filter(|principal| principal.kind == PrincipalKind::Agent)
        .map(|principal| agent_json(&principal))
        .collect();
    HttpResponse::ok_json(JsonValue::Object(vec![(
        "agents".to_string(),
        JsonValue::Array(agents),
    )]))
}

fn agent(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    path: &str,
    request: &HttpRequest,
) -> HttpResponse {
    let tenant = match tenant_from_request(runtime, request) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(id) = path_id(path, "/_authport/agents/") else {
        return HttpResponse::bad_request("missing agent id");
    };
    match runtime
        .mesh()
        .stores()
        .principals
        .get_principal(&tenant, &PrincipalId(id.to_string()))
    {
        Ok(Some(principal)) if principal.kind == PrincipalKind::Agent => {
            HttpResponse::ok_json(agent_json(&principal))
        }
        Ok(_) => HttpResponse::denied(404, "not_found", "agent not found"),
        Err(err) => HttpResponse::bad_request(&err.message),
    }
}

fn create_agent(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    let tenant = match tenant_from_request(runtime, request) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let body = String::from_utf8_lossy(&request.body);
    let name = extract_quoted_field(&body, "name").unwrap_or_else(|| "agent".to_string());
    let id = extract_quoted_field(&body, "id")
        .unwrap_or_else(|| format!("agent:{}", name.replace(' ', "-")));
    let principal = Principal::agent(
        PrincipalId(id),
        tenant.tenant_id.clone(),
        Claims {
            values: Default::default(),
        },
        ContractVersion { major: 1, minor: 0 },
        AgentState::Active,
    );
    match runtime
        .mesh()
        .stores()
        .principals
        .put_principal(principal.clone())
    {
        Ok(()) => HttpResponse::ok_json(agent_json(&principal)),
        Err(err) => HttpResponse::bad_request(&err.message),
    }
}

fn agent_runs(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    path: &str,
    request: &HttpRequest,
) -> HttpResponse {
    let Some(tenant) = request_value(request, "tenant") else {
        return HttpResponse::bad_request("missing tenant");
    };
    let Some(agent_id) = path_id(path, "/_authport/agents/") else {
        return HttpResponse::bad_request("missing agent id");
    };
    let agent_id = agent_id.trim_end_matches("/runs");
    match runtime.agent_runs(&tenant, &PrincipalId(agent_id.to_string())) {
        Ok(runs) => HttpResponse::ok_json(JsonValue::Object(vec![(
            "runs".to_string(),
            JsonValue::Array(runs.iter().map(run_json).collect()),
        )])),
        Err(err) => HttpResponse::denied(
            crate::server::status_for(&err.denial),
            err.denial.as_str(),
            &err.message,
        ),
    }
}

fn agent_run(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    path: &str,
    request: &HttpRequest,
) -> HttpResponse {
    let Some(tenant) = request_value(request, "tenant") else {
        return HttpResponse::bad_request("missing tenant");
    };
    let Some(id) = path_id(path, "/_authport/runs/") else {
        return HttpResponse::bad_request("missing run id");
    };
    match runtime.agent_run(&tenant, &RunId(id.to_string())) {
        Ok(Some(run)) => HttpResponse::ok_json(run_json(&run)),
        Ok(None) => HttpResponse::denied(404, "run_not_found", "run not found"),
        Err(err) => HttpResponse::denied(
            crate::server::status_for(&err.denial),
            err.denial.as_str(),
            &err.message,
        ),
    }
}

fn create_agent_run(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    path: &str,
    request: &HttpRequest,
) -> HttpResponse {
    let body = String::from_utf8_lossy(&request.body);
    let Some(tenant) = request_value(request, "tenant") else {
        return HttpResponse::bad_request("missing tenant");
    };
    let Some(agent_id) = path_id(path, "/_authport/agents/") else {
        return HttpResponse::bad_request("missing agent id");
    };
    let agent_id = agent_id.trim_end_matches("/runs");
    let Some(delegation_id) = extract_quoted_field(&body, "delegation_id")
        .or_else(|| extract_quoted_field(&body, "delegation"))
    else {
        return HttpResponse::bad_request("missing delegation_id");
    };
    let capabilities = capability_fields(&body);
    if capabilities.is_empty() {
        return HttpResponse::bad_request("missing capability");
    }
    let Some(expires_at) = extract_number_field(&body, "expires_at") else {
        return HttpResponse::bad_request("missing expires_at");
    };
    let task_id = extract_quoted_field(&body, "task_id")
        .unwrap_or_else(|| format!("task:{}", agent_id.replace(':', "-")));
    let task_purpose = extract_quoted_field(&body, "purpose")
        .or_else(|| extract_quoted_field(&body, "task_purpose"))
        .unwrap_or_else(|| "agent run".to_string());
    let run_id = extract_quoted_field(&body, "id").map(RunId);
    let parent_run_id = extract_quoted_field(&body, "parent_run_id").map(RunId);
    let request = RunCreationRequest {
        id: run_id,
        task_id: TaskId(task_id),
        task_purpose,
        delegation_id: DelegationId(delegation_id),
        parent_run_id,
        capabilities,
        resource_scope: resource_scope_from_body(&body),
        expires_at,
        constraints: Vec::new(),
    };
    match runtime.create_agent_run(&tenant, &PrincipalId(agent_id.to_string()), request) {
        Ok(run) => HttpResponse::ok_json(run_json(&run)),
        Err(err) => HttpResponse::denied(
            crate::server::status_for(&err.denial),
            err.denial.as_str(),
            &err.message,
        ),
    }
}

fn cancel_agent_run(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    path: &str,
    request: &HttpRequest,
) -> HttpResponse {
    let Some(tenant) = request_value(request, "tenant") else {
        return HttpResponse::bad_request("missing tenant");
    };
    let Some(id) = path_id(path, "/_authport/runs/") else {
        return HttpResponse::bad_request("missing run id");
    };
    let run_id = id.trim_end_matches("/cancel");
    match runtime.cancel_agent_run(&tenant, &RunId(run_id.to_string())) {
        Ok(run) => HttpResponse::ok_json(run_json(&run)),
        Err(err) => HttpResponse::denied(
            crate::server::status_for(&err.denial),
            err.denial.as_str(),
            &err.message,
        ),
    }
}

fn set_agent_state(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    path: &str,
    request: &HttpRequest,
    state: AgentState,
) -> HttpResponse {
    let tenant_id = match request_value(request, "tenant") {
        Some(tenant) => tenant,
        None => return HttpResponse::bad_request("missing tenant"),
    };
    let Some(id) = path_id(path, "/_authport/agents/") else {
        return HttpResponse::bad_request("missing agent id");
    };
    let agent_id = id
        .trim_end_matches("/suspend")
        .trim_end_matches("/revoke")
        .trim_end_matches("/retire");
    let result = match state {
        AgentState::Suspended => runtime.mesh().suspend_agent(
            &tenant_id,
            &PrincipalId(agent_id.to_string()),
            runtime.now(),
        ),
        AgentState::Revoked => runtime.mesh().revoke_agent(
            &tenant_id,
            &PrincipalId(agent_id.to_string()),
            runtime.now(),
        ),
        AgentState::Retired => runtime.mesh().retire_agent(
            &tenant_id,
            &PrincipalId(agent_id.to_string()),
            runtime.now(),
        ),
        _ => Ok(()),
    };
    match result {
        Ok(()) => HttpResponse::ok_json(JsonValue::Object(vec![
            ("id".to_string(), JsonValue::String(agent_id.to_string())),
            (
                "status".to_string(),
                JsonValue::String(agent_state(&state).to_string()),
            ),
        ])),
        Err(err) => HttpResponse::denied(
            crate::server::status_for(&err.denial),
            err.denial.as_str(),
            &err.message,
        ),
    }
}

fn delegations(runtime: &std::sync::Arc<AuthPortRuntime>, request: &HttpRequest) -> HttpResponse {
    let tenant = match tenant_from_request(runtime, request) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(delegate) = request_value(request, "delegate") else {
        return HttpResponse::bad_request("missing delegate");
    };
    let delegations = runtime
        .mesh()
        .delegations_for(&tenant, &PrincipalId(delegate))
        .unwrap_or_default()
        .into_iter()
        .map(|delegation| delegation_json(&delegation))
        .collect();
    HttpResponse::ok_json(JsonValue::Object(vec![(
        "delegations".to_string(),
        JsonValue::Array(delegations),
    )]))
}

fn delegation(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    path: &str,
    request: &HttpRequest,
) -> HttpResponse {
    let tenant = match tenant_from_request(runtime, request) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(id) = path_id(path, "/_authport/delegations/") else {
        return HttpResponse::bad_request("missing delegation id");
    };
    match runtime
        .mesh()
        .stores()
        .delegations
        .get_delegation(&tenant, &DelegationId(id.to_string()))
    {
        Ok(Some(delegation)) => HttpResponse::ok_json(delegation_json(&delegation)),
        Ok(None) => HttpResponse::denied(404, "not_found", "delegation not found"),
        Err(err) => HttpResponse::bad_request(&err.message),
    }
}

fn create_delegation(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    request: &HttpRequest,
) -> HttpResponse {
    let body = String::from_utf8_lossy(&request.body);
    let Some(tenant) = request_value(request, "tenant") else {
        return HttpResponse::bad_request("missing tenant");
    };
    let Some(id) = extract_quoted_field(&body, "id") else {
        return HttpResponse::bad_request("missing id");
    };
    let Some(delegator) = extract_quoted_field(&body, "delegator") else {
        return HttpResponse::bad_request("missing delegator");
    };
    let Some(delegate) = extract_quoted_field(&body, "delegate") else {
        return HttpResponse::bad_request("missing delegate");
    };
    let Some(capability) = extract_quoted_field(&body, "capability") else {
        return HttpResponse::bad_request("missing capability");
    };
    let expires_at = extract_number_field(&body, "expires_at");
    match runtime.mesh().delegate(
        &tenant,
        DelegationRequest {
            id: DelegationId(id),
            delegator: PrincipalId(delegator),
            delegate: PrincipalId(delegate),
            capabilities: vec![capability.into()],
            resource_scope: ResourceScope::any(),
            issued_at: runtime.now(),
            expires_at,
        },
        runtime.now(),
    ) {
        Ok(delegation) => HttpResponse::ok_json(delegation_json(&delegation)),
        Err(err) => HttpResponse::denied(
            crate::server::status_for(&err.denial),
            err.denial.as_str(),
            &err.message,
        ),
    }
}

fn revoke_delegation(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    path: &str,
    request: &HttpRequest,
) -> HttpResponse {
    let Some(tenant) = request_value(request, "tenant") else {
        return HttpResponse::bad_request("missing tenant");
    };
    let Some(id) = path_id(path, "/_authport/delegations/") else {
        return HttpResponse::bad_request("missing delegation id");
    };
    let delegation_id = id.trim_end_matches("/revoke");
    match runtime.mesh().revoke_delegation(
        &tenant,
        &DelegationId(delegation_id.to_string()),
        runtime.now(),
    ) {
        Ok(()) => HttpResponse::ok_json(JsonValue::Object(vec![
            (
                "id".to_string(),
                JsonValue::String(delegation_id.to_string()),
            ),
            (
                "status".to_string(),
                JsonValue::String("revoked".to_string()),
            ),
        ])),
        Err(err) => HttpResponse::denied(
            crate::server::status_for(&err.denial),
            err.denial.as_str(),
            &err.message,
        ),
    }
}

fn tenant_from_request(
    runtime: &std::sync::Arc<AuthPortRuntime>,
    request: &HttpRequest,
) -> Result<appport_auth_mesh_contract::TenantContext, HttpResponse> {
    let tenant_id = request_value(request, "tenant")
        .ok_or_else(|| HttpResponse::bad_request("missing tenant"))?;
    runtime.mesh().tenant(&tenant_id).map_err(|err| {
        HttpResponse::denied(
            crate::server::status_for(&err.denial),
            err.denial.as_str(),
            &err.message,
        )
    })
}

fn request_value(request: &HttpRequest, field: &str) -> Option<String> {
    request.query.get(field).cloned().or_else(|| {
        let body = String::from_utf8_lossy(&request.body);
        extract_quoted_field(&body, field)
    })
}

fn path_id<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.strip_prefix(prefix).filter(|id| !id.is_empty())
}

fn agent_json(principal: &Principal) -> JsonValue {
    JsonValue::Object(vec![
        (
            "id".to_string(),
            JsonValue::String(principal.id.to_string()),
        ),
        ("kind".to_string(), JsonValue::String("agent".to_string())),
        (
            "tenant".to_string(),
            JsonValue::String(principal.tenant_id.to_string()),
        ),
        (
            "status".to_string(),
            JsonValue::String(
                principal
                    .agent_state
                    .as_ref()
                    .map(agent_state)
                    .unwrap_or("unknown")
                    .to_string(),
            ),
        ),
    ])
}

fn delegation_json(delegation: &appport_auth_mesh_contract::Delegation) -> JsonValue {
    JsonValue::Object(vec![
        (
            "id".to_string(),
            JsonValue::String(delegation.id.to_string()),
        ),
        (
            "delegator".to_string(),
            JsonValue::String(delegation.delegator.to_string()),
        ),
        (
            "delegate".to_string(),
            JsonValue::String(delegation.delegate.to_string()),
        ),
        (
            "expires_at".to_string(),
            delegation
                .expires_at
                .map(|expires_at| JsonValue::Number(expires_at as f64))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "status".to_string(),
            JsonValue::String(if delegation.revoked_at.is_some() {
                "revoked".to_string()
            } else {
                "active".to_string()
            }),
        ),
    ])
}

fn run_json(run: &AgentRun) -> JsonValue {
    JsonValue::Object(vec![
        ("id".to_string(), JsonValue::String(run.id.to_string())),
        (
            "agent_principal".to_string(),
            JsonValue::String(run.agent_principal.to_string()),
        ),
        (
            "delegator".to_string(),
            JsonValue::String(run.delegator.to_string()),
        ),
        (
            "delegation_id".to_string(),
            JsonValue::String(run.delegation_id.to_string()),
        ),
        (
            "delegation_chain".to_string(),
            JsonValue::Array(
                run.delegation_chain
                    .iter()
                    .map(|id| JsonValue::String(id.to_string()))
                    .collect(),
            ),
        ),
        (
            "parent_run_id".to_string(),
            run.parent_run_id
                .as_ref()
                .map(|id| JsonValue::String(id.to_string()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "task_id".to_string(),
            JsonValue::String(run.task.id.to_string()),
        ),
        (
            "task_purpose".to_string(),
            JsonValue::String(run.task.purpose.clone()),
        ),
        (
            "capability_scope".to_string(),
            JsonValue::Array(
                run.capability_scope
                    .iter()
                    .map(|capability| JsonValue::String(capability.to_string()))
                    .collect(),
            ),
        ),
        (
            "resource_scope".to_string(),
            resource_scope_json(&run.resource_scope),
        ),
        (
            "created_at".to_string(),
            JsonValue::Number(run.created_at as f64),
        ),
        (
            "expires_at".to_string(),
            JsonValue::Number(run.expires_at as f64),
        ),
        (
            "status".to_string(),
            JsonValue::String(run.status.as_str().to_string()),
        ),
        (
            "authority_revision".to_string(),
            JsonValue::Number(run.authority_revision as f64),
        ),
        (
            "contract_fingerprint".to_string(),
            JsonValue::String(run.contract_fingerprint.clone()),
        ),
        (
            "execution_credential".to_string(),
            JsonValue::String(run.execution_credential.to_string()),
        ),
    ])
}

fn resource_scope_json(scope: &ResourceScope) -> JsonValue {
    JsonValue::Object(vec![
        (
            "resource_type".to_string(),
            scope
                .resource_type
                .as_ref()
                .map(|value| JsonValue::String(value.clone()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "resource_id".to_string(),
            scope
                .resource_id
                .as_ref()
                .map(|value| JsonValue::String(value.clone()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "attributes".to_string(),
            JsonValue::Object(
                scope
                    .attributes
                    .iter()
                    .map(|(key, value)| (key.clone(), claim_value_json(value)))
                    .collect(),
            ),
        ),
    ])
}

fn claim_value_json(value: &ClaimValue) -> JsonValue {
    match value {
        ClaimValue::Enum(value) | ClaimValue::String(value) => JsonValue::String(value.clone()),
        ClaimValue::Integer(value) => JsonValue::Number(*value as f64),
        ClaimValue::Boolean(value) => JsonValue::Bool(*value),
    }
}

fn capability_fields(body: &str) -> Vec<Capability> {
    extract_quoted_field(body, "capabilities")
        .or_else(|| extract_quoted_field(body, "capability"))
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| Capability(value.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn resource_scope_from_body(body: &str) -> ResourceScope {
    let mut scope = match (
        extract_quoted_field(body, "resource_type"),
        extract_quoted_field(body, "resource_id"),
    ) {
        (Some(resource_type), Some(resource_id)) => {
            ResourceScope::exact(resource_type, resource_id)
        }
        (Some(resource_type), None) => ResourceScope::resource(resource_type),
        _ => ResourceScope::any(),
    };
    if let Some(tenant) = extract_quoted_field(body, "resource_tenant")
        .or_else(|| extract_quoted_field(body, "tenant_scope"))
    {
        scope = scope.with_attribute("tenant", ClaimValue::Enum(tenant));
    }
    if let Some(status) = extract_quoted_field(body, "status") {
        scope = scope.with_attribute("status", ClaimValue::Enum(status));
    }
    if let Some(department) = extract_quoted_field(body, "department") {
        scope = scope.with_attribute("department", ClaimValue::Enum(department));
    }
    scope
}

fn agent_state(state: &AgentState) -> &'static str {
    match state {
        AgentState::Created => "created",
        AgentState::Active => "active",
        AgentState::Suspended => "suspended",
        AgentState::Revoked => "revoked",
        AgentState::Retired => "retired",
    }
}

fn extract_number_field(json: &str, field: &str) -> Option<i64> {
    let pattern = format!("\"{}\":", field);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let digits = rest
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '-')
        .collect::<String>();
    digits.parse().ok()
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
    } else if body_str.contains("password_policy") || body_str.contains("set_password_policy") {
        Ok(AuthorityChange::SetPasswordPolicy {
            policy: password_policy_from_body(&body_str)?,
        })
    } else if body_str.contains("revert") {
        let change_id = extract_quoted_field(&body_str, "change_id").ok_or("missing change_id")?;
        Ok(AuthorityChange::Revert { change_id })
    } else {
        Err("unknown action".to_string())
    }
}

fn password_policy_from_body(body: &str) -> Result<PasswordPolicy, String> {
    let mut policy = PasswordPolicy::default();
    if let Some(value) = extract_number_field(body, "min_length") {
        policy.min_length = usize::try_from(value).map_err(|_| "invalid min_length")?;
    }
    if let Some(value) = extract_number_field(body, "max_length") {
        policy.max_length = usize::try_from(value).map_err(|_| "invalid max_length")?;
    }
    if let Some(value) = extract_bool_field(body, "require_uppercase") {
        policy.require_uppercase = value;
    }
    if let Some(value) = extract_bool_field(body, "require_lowercase") {
        policy.require_lowercase = value;
    }
    if let Some(value) = extract_bool_field(body, "require_number") {
        policy.require_number = value;
    }
    if let Some(value) = extract_bool_field(body, "require_special_character") {
        policy.require_special_character = value;
    }
    if body.contains("\"expiration_days\": null")
        || body.contains("\"password_expiration_days\": null")
    {
        policy.password_expiration_days = None;
    } else if let Some(value) = extract_number_field(body, "expiration_days")
        .or_else(|| extract_number_field(body, "password_expiration_days"))
    {
        policy.password_expiration_days =
            Some(u32::try_from(value).map_err(|_| "invalid expiration_days")?);
    }
    if let Some(value) = extract_number_field(body, "history_count")
        .or_else(|| extract_number_field(body, "password_history_count"))
    {
        policy.password_history_count =
            usize::try_from(value).map_err(|_| "invalid history_count")?;
    }
    if let Some(value) = extract_bool_field(body, "allow_password_change") {
        policy.allow_password_change = value;
    }
    if let Some(value) = extract_bool_field(body, "allow_password_reset") {
        policy.allow_password_reset = value;
    }
    policy.validate().map_err(|err| err.message)?;
    Ok(policy)
}

fn extract_bool_field(json: &str, field: &str) -> Option<bool> {
    let pattern = format!("\"{}\":", field);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
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
        (
            "password_policy".to_string(),
            state
                .password_policy
                .as_ref()
                .map(password_policy_json_value)
                .unwrap_or(JsonValue::Null),
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
        AuthorityChange::SetPasswordPolicy { policy } => JsonValue::Object(vec![
            (
                "type".to_string(),
                JsonValue::String("set_password_policy".to_string()),
            ),
            ("policy".to_string(), password_policy_json_value(policy)),
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

fn password_policy_json_value(policy: &PasswordPolicy) -> JsonValue {
    JsonValue::Object(vec![
        (
            "min_length".to_string(),
            JsonValue::Number(policy.min_length as f64),
        ),
        (
            "max_length".to_string(),
            JsonValue::Number(policy.max_length as f64),
        ),
        (
            "require_uppercase".to_string(),
            JsonValue::Bool(policy.require_uppercase),
        ),
        (
            "require_lowercase".to_string(),
            JsonValue::Bool(policy.require_lowercase),
        ),
        (
            "require_number".to_string(),
            JsonValue::Bool(policy.require_number),
        ),
        (
            "require_special_character".to_string(),
            JsonValue::Bool(policy.require_special_character),
        ),
        (
            "expiration_days".to_string(),
            policy
                .password_expiration_days
                .map(|days| JsonValue::Number(days as f64))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "history_count".to_string(),
            JsonValue::Number(policy.password_history_count as f64),
        ),
    ])
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
