//! The full path, once:
//!
//! ```text
//! DSL -> AuthConfig -> ConnectorRegistry -> Authentication -> ExternalIdentity
//!     -> Principal -> Tenant -> Session -> Claims -> Authorization
//!     -> CapabilityEnvelope -> Delegation -> Agent -> RuntimeContext
//! ```

use std::sync::Arc;

use appport_auth_mesh_authz::{
    Action, AuthorityBasis, AuthorizationContext, AuthorizationDecision, CapabilityEnvelope,
    Condition, DenialReason, Policy, ResourceAttributes, ResourceRef, Rule,
};
use appport_auth_mesh_contract::{
    Capability, ClaimValue, Claims, Delegation, DelegationId, Principal, PrincipalId,
    PrincipalKind, ResourceScope, SessionId, TenantContext,
};
use appport_auth_mesh_dsl::{parse_auth_block, AuthConfig};
use appport_auth_mesh_providers::{
    AuthConnector, AuthRequest, AuthResponse, ConnectorRegistry, LocalAccount, LocalConnector,
};
use appport_auth_mesh_runtime::{
    AuthError, AuthMesh, AuthenticatedSession, DelegationRequest, MemoryStores, Registration,
    RuntimeContext,
};
use appport_auth_mesh_storage::{AuditEventKind, TenantRootStore};
use appport_auth_mesh_surface::AuthSurface;

const DECLARATION: &str = r#"
use auth {
  providers = [local]
  tenant = true

  claims = {
    role = enum["owner", "admin", "member"]
    plan = enum["free", "pro"]
  }

  agents = true
}
"#;

const NOW: i64 = 1_000;

fn tenant(id: &str) -> TenantContext {
    TenantContext {
        tenant_id: id.into(),
        namespace: id.to_string(),
        policy_id: format!("{}-policy", id).into(),
        storage_root_id: format!("{}-root", id).into(),
    }
}

fn policy_for(tenant: &TenantContext) -> Policy {
    Policy {
        id: tenant.policy_id.clone(),
        rules: vec![
            Rule::allow(
                Capability("invoice.create".to_string()),
                Condition::ClaimIn {
                    key: "role".to_string(),
                    values: vec![
                        ClaimValue::Enum("owner".to_string()),
                        ClaimValue::Enum("admin".to_string()),
                    ],
                },
            ),
            Rule::allow(
                Capability("reports.export".to_string()),
                Condition::ClaimEquals {
                    key: "plan".to_string(),
                    value: ClaimValue::Enum("pro".to_string()),
                },
            ),
            Rule::allow(
                Capability("billing.charge".to_string()),
                Condition::ClaimEquals {
                    key: "role".to_string(),
                    value: ClaimValue::Enum("owner".to_string()),
                },
            ),
        ],
    }
}

fn directory() -> LocalConnector {
    LocalConnector::new()
        .with_account(
            LocalAccount::new("alice", "alice-secret").with_attribute("email", "alice@acme.test"),
        )
        .with_account(LocalAccount::new("invoice-agent", "agent-secret"))
        .with_account(LocalAccount::new("bob", "bob-secret"))
        .with_account(LocalAccount::new("carol", "carol-secret"))
}

fn config() -> AuthConfig {
    parse_auth_block(DECLARATION).expect("the declaration is valid")
}

fn registry() -> ConnectorRegistry {
    ConnectorRegistry::from_config_with(&config(), vec![Arc::new(directory())])
        .expect("connectors resolve from the declaration")
}

fn credentials(tenant_id: &str, username: &str, password: &str) -> AuthResponse {
    AuthResponse::to_challenge(
        &LocalConnector::new()
            .begin(
                &AuthRequest::new("local")
                    .for_tenant(tenant_id)
                    .with_parameter("username", username),
            )
            .expect("challenge"),
    )
    .for_tenant(tenant_id)
    .with_parameter("username", username)
    .with_parameter("password", password)
}

fn capability(name: &str) -> Capability {
    Capability(name.to_string())
}

fn assert_allows(envelope: &CapabilityEnvelope, name: &str) {
    assert!(
        envelope.allows(&capability(name)),
        "expected the envelope to grant `{name}`: {:?}",
        envelope.capabilities()
    );
}

fn assert_denies(decision: &AuthorizationDecision, expected: DenialReason) {
    match decision {
        AuthorizationDecision::Allow { grant, .. } => {
            panic!(
                "expected deny ({expected:?}), got allow: {}",
                grant.explain()
            )
        }
        AuthorizationDecision::Deny { reason, .. } => assert_eq!(reason, &expected),
    }
}

/// Setup shared by the scenarios: two tenants, their policies, Alice, Bob and
/// the invoice agent.
fn provision(stores: &MemoryStores) {
    let tenant_a = tenant("tenant-a");
    let tenant_b = tenant("tenant-b");
    stores.tenants.put_tenant(tenant_a.clone()).unwrap();
    stores.tenants.put_tenant(tenant_b.clone()).unwrap();
    stores.policies.put(policy_for(&tenant_a)).unwrap();
    stores.policies.put(policy_for(&tenant_b)).unwrap();
}

fn sign_up_cast(
    mesh: &AuthMesh,
) -> (
    AuthenticatedSession,
    AuthenticatedSession,
    AuthenticatedSession,
) {
    let alice = mesh
        .sign_up(
            "tenant-a",
            &credentials("tenant-a", "alice", "alice-secret"),
            Registration::human()
                .with_claim("role", "admin")
                .with_claim("plan", "pro"),
            NOW,
        )
        .expect("Alice registers in tenant A");

    let agent = mesh
        .sign_up(
            "tenant-a",
            &credentials("tenant-a", "invoice-agent", "agent-secret"),
            Registration::agent(),
            NOW,
        )
        .expect("the invoice agent registers in tenant A");

    let bob = mesh
        .sign_up(
            "tenant-b",
            &credentials("tenant-b", "bob", "bob-secret"),
            Registration::human()
                .with_claim("role", "owner")
                .with_claim("plan", "free"),
            NOW,
        )
        .expect("Bob registers in tenant B");

    (alice, agent, bob)
}

#[test]
fn declaration_flows_all_the_way_to_a_runtime_context() {
    let stores = MemoryStores::new();
    provision(&stores);
    let mesh = AuthMesh::new(config(), registry(), stores.mesh_stores()).expect("mesh builds");

    // DSL -> AuthConfig -> AuthSurface
    assert_eq!(mesh.surface(), &AuthSurface::derive(&config()));
    assert!(mesh.surface().exposes("/auth/agents"));

    let (alice, agent, _bob) = sign_up_cast(&mesh);

    // Connector -> ExternalIdentity -> Principal
    assert_eq!(alice.external.connector, "local");
    assert_eq!(alice.external.subject, "alice");
    assert_eq!(alice.principal().kind, PrincipalKind::Human);
    assert_eq!(alice.context.tenant.tenant_id, "tenant-a".into());

    // Session -> Claims
    let context = mesh
        .session_context("tenant-a", &alice.session.id, NOW + 10)
        .expect("Alice's session resolves");
    assert_eq!(context.principal.id, alice.principal().id);
    assert_eq!(
        context.claims.values.get("role"),
        Some(&ClaimValue::Enum("admin".to_string()))
    );

    // Claims -> Authorization -> CapabilityEnvelope
    assert_allows(&context.capabilities, "invoice.create");
    assert_allows(&context.capabilities, "reports.export");
    assert!(!context.capabilities.allows(&capability("billing.charge")));

    let decision = mesh.authorize(&context, &capability("invoice.create"), NOW + 10);
    let grant = decision.grant().expect("Alice may create invoices");
    assert_eq!(grant.principal_id, alice.principal().id);
    assert_eq!(grant.authority, AuthorityBasis::Claim);
    assert_eq!(grant.delegated_by, None);
    assert!(grant.explain().contains("authority: claim"));
    assert_denies(
        &mesh.authorize(&context, &capability("billing.charge"), NOW + 10),
        DenialReason::DelegationMissing,
    );

    // Human and agent are distinct principals, both authenticated.
    assert_eq!(agent.principal().kind, PrincipalKind::Agent);
    assert_ne!(agent.principal().id, alice.principal().id);
    assert!(agent.principal().claims.values.is_empty());

    // ... and an agent holds nothing until authority is delegated to it.
    let agent_context = mesh
        .session_context("tenant-a", &agent.session.id, NOW + 10)
        .expect("the agent's session resolves");
    assert!(agent_context.capabilities.capabilities().is_empty());
    assert_denies(
        &mesh.authorize(&agent_context, &capability("invoice.create"), NOW + 10),
        DenialReason::DelegationMissing,
    );

    // Delegation -> Agent -> RuntimeContext
    let delegation = mesh
        .delegate(
            "tenant-a",
            DelegationRequest {
                id: DelegationId("delegation-invoices".to_string()),
                delegator: alice.principal().id.clone(),
                delegate: agent.principal().id.clone(),
                capabilities: vec![capability("invoice.create")],
                resource_scope: appport_auth_mesh_contract::ResourceScope::any(),
                issued_at: NOW,
                expires_at: Some(NOW + 1_000),
            },
            NOW,
        )
        .expect("Alice delegates invoice creation");

    let agent_context = mesh
        .session_context("tenant-a", &agent.session.id, NOW + 20)
        .expect("the agent's session resolves");
    assert_allows(&agent_context.capabilities, "invoice.create");
    assert!(!agent_context
        .capabilities
        .allows(&capability("reports.export")));

    let decision = mesh.authorize(&agent_context, &capability("invoice.create"), NOW + 20);
    let grant = decision.grant().expect("the agent acts under delegation");
    assert_eq!(grant.principal_id, agent.principal().id);
    assert_eq!(grant.principal_kind, PrincipalKind::Agent);
    assert_eq!(grant.authority, AuthorityBasis::Delegated);
    assert_eq!(grant.delegation_id, Some(delegation.id.clone()));
    assert_eq!(grant.delegated_by, Some(alice.principal().id.clone()));

    // principal = agent, delegated_by = human. Never collapsed.
    assert_eq!(agent_context.delegated_by(), Some(&alice.principal().id));
    assert!(agent_context.is_agent());
    assert_ne!(agent_context.principal.id, alice.principal().id);

    let explanation = grant.explain();
    assert!(explanation.contains("invoice.create"));
    assert!(explanation.contains("authority: delegated"));
    assert!(explanation.contains(&format!("delegation: {}", delegation.id)));
    assert!(explanation.contains(&format!("delegated_by: {}", alice.principal().id)));

    // Both principal kinds are answered by the same policy engine.
    assert!(decision.grant().unwrap().policy_id == grant.policy_id);
}

#[test]
fn delegation_cannot_exceed_the_delegators_own_authority() {
    let stores = MemoryStores::new();
    provision(&stores);
    let mesh = AuthMesh::new(config(), registry(), stores.mesh_stores()).expect("mesh builds");
    let (alice, agent, _bob) = sign_up_cast(&mesh);

    // Alice is an admin, not an owner: she cannot pass on `billing.charge`.
    let err = mesh
        .delegate(
            "tenant-a",
            DelegationRequest {
                id: DelegationId("delegation-billing".to_string()),
                delegator: alice.principal().id.clone(),
                delegate: agent.principal().id.clone(),
                capabilities: vec![capability("billing.charge")],
                resource_scope: appport_auth_mesh_contract::ResourceScope::any(),
                issued_at: NOW,
                expires_at: Some(NOW + 1_000),
            },
            NOW,
        )
        .expect_err("authority cannot be widened by delegating it");
    assert_eq!(err.denial, DenialReason::DelegationExceedsAuthority);

    // A delegation with no end is not a delegation.
    let err = mesh
        .delegate(
            "tenant-a",
            DelegationRequest {
                id: DelegationId("delegation-forever".to_string()),
                delegator: alice.principal().id.clone(),
                delegate: agent.principal().id.clone(),
                capabilities: vec![capability("invoice.create")],
                resource_scope: appport_auth_mesh_contract::ResourceScope::any(),
                issued_at: NOW,
                expires_at: Some(NOW),
            },
            NOW,
        )
        .expect_err("delegations are time-bound");
    assert_eq!(err.denial, DenialReason::InvalidDelegation);
}

#[test]
fn revoking_a_delegation_removes_agent_authority() {
    let stores = MemoryStores::new();
    provision(&stores);
    let mesh = AuthMesh::new(config(), registry(), stores.mesh_stores()).expect("mesh builds");
    let (alice, agent, _bob) = sign_up_cast(&mesh);

    let delegation = mesh
        .delegate(
            "tenant-a",
            DelegationRequest {
                id: DelegationId("delegation-invoices".to_string()),
                delegator: alice.principal().id.clone(),
                delegate: agent.principal().id.clone(),
                capabilities: vec![capability("invoice.create")],
                resource_scope: appport_auth_mesh_contract::ResourceScope::any(),
                issued_at: NOW,
                expires_at: Some(NOW + 1_000),
            },
            NOW,
        )
        .unwrap();

    mesh.revoke_delegation("tenant-a", &delegation.id, NOW + 500)
        .expect("Alice revokes the delegation");

    let agent_context = mesh
        .session_context("tenant-a", &agent.session.id, NOW + 600)
        .expect("the agent still has a session");
    assert!(agent_context.capabilities.capabilities().is_empty());
    assert_denies(
        &mesh.authorize(&agent_context, &capability("invoice.create"), NOW + 600),
        DenialReason::RevokedDelegation,
    );

    // Alice keeps her own authority: revocation removes the agent's, not hers.
    let alice_context = mesh
        .session_context("tenant-a", &alice.session.id, NOW + 600)
        .unwrap();
    assert!(mesh
        .authorize(&alice_context, &capability("invoice.create"), NOW + 600)
        .is_allowed());

    // Every decision is recorded.
    let events = stores.audit_events();
    assert!(events
        .iter()
        .any(|event| event.kind == AuditEventKind::DelegationCreated));
    assert!(events
        .iter()
        .any(|event| event.kind == AuditEventKind::DelegationRevoked));
    assert!(events.iter().any(|event| {
        event.kind == AuditEventKind::AuthorizationDenied
            && event.metadata.get("reason").map(String::as_str) == Some("delegation_revoked")
    }));
}

#[test]
fn an_expired_delegation_stops_granting_authority() {
    let stores = MemoryStores::new();
    provision(&stores);
    let mesh = AuthMesh::new(config(), registry(), stores.mesh_stores()).expect("mesh builds");
    let (alice, agent, _bob) = sign_up_cast(&mesh);

    mesh.delegate(
        "tenant-a",
        DelegationRequest {
            id: DelegationId("delegation-short".to_string()),
            delegator: alice.principal().id.clone(),
            delegate: agent.principal().id.clone(),
            capabilities: vec![capability("invoice.create")],
            resource_scope: appport_auth_mesh_contract::ResourceScope::any(),
            issued_at: NOW,
            expires_at: Some(NOW + 100),
        },
        NOW,
    )
    .unwrap();

    let context = mesh
        .session_context("tenant-a", &agent.session.id, NOW + 50)
        .unwrap();
    assert!(mesh
        .authorize(&context, &capability("invoice.create"), NOW + 50)
        .is_allowed());

    let context = mesh
        .session_context("tenant-a", &agent.session.id, NOW + 200)
        .unwrap();
    assert!(context.capabilities.capabilities().is_empty());
    assert_denies(
        &mesh.authorize(&context, &capability("invoice.create"), NOW + 200),
        DenialReason::ExpiredDelegation,
    );
}

#[test]
fn delegated_authority_is_limited_by_resource_scope() {
    let stores = MemoryStores::new();
    provision(&stores);
    let mesh = AuthMesh::new(config(), registry(), stores.mesh_stores()).expect("mesh builds");
    let (alice, agent, _bob) = sign_up_cast(&mesh);

    mesh.delegate(
        "tenant-a",
        DelegationRequest {
            id: DelegationId("delegation-finance".to_string()),
            delegator: alice.principal().id.clone(),
            delegate: agent.principal().id.clone(),
            capabilities: vec![capability("invoice.create")],
            resource_scope: ResourceScope::resource("invoice")
                .with_attribute("department", ClaimValue::Enum("finance".to_string())),
            issued_at: NOW,
            expires_at: Some(NOW + 1_000),
        },
        NOW,
    )
    .unwrap();

    let context = mesh
        .session_context("tenant-a", &agent.session.id, NOW + 10)
        .unwrap();
    let request = appport_auth_mesh_authz::AuthorizationRequest {
        principal: agent.principal().id.clone(),
        tenant: "tenant-a".into(),
        capability: capability("invoice.create"),
        action: Action("create".to_string()),
        resource: Some(ResourceRef::new("invoice", "8472", "tenant-a")),
        context: AuthorizationContext::default(),
    };
    let finance_invoice = ResourceAttributes::new()
        .with_tenant("tenant-a")
        .with_value("department", ClaimValue::Enum("finance".to_string()));
    assert!(mesh
        .authorize_request(&context, &request, Some(&finance_invoice), NOW + 10)
        .is_allowed());

    let sales_invoice = ResourceAttributes::new()
        .with_tenant("tenant-a")
        .with_value("department", ClaimValue::Enum("sales".to_string()));
    assert_denies(
        &mesh.authorize_request(&context, &request, Some(&sales_invoice), NOW + 10),
        DenialReason::DelegationScopeDenied,
    );
}

#[test]
fn chained_delegation_preserves_attenuated_scope_and_evidence() {
    let stores = MemoryStores::new();
    provision(&stores);
    let mesh = AuthMesh::new(config(), registry(), stores.mesh_stores()).expect("mesh builds");
    let (alice, manager, _bob) = sign_up_cast(&mesh);
    let invoice_agent = mesh
        .sign_up(
            "tenant-a",
            &credentials("tenant-a", "carol", "carol-secret"),
            Registration::agent(),
            NOW,
        )
        .unwrap();

    let parent_scope = ResourceScope::resource("invoice")
        .with_attribute("department", ClaimValue::Enum("finance".to_string()));
    let parent = mesh
        .delegate(
            "tenant-a",
            DelegationRequest {
                id: DelegationId("delegation-manager".to_string()),
                delegator: alice.principal().id.clone(),
                delegate: manager.principal().id.clone(),
                capabilities: vec![capability("invoice.create")],
                resource_scope: parent_scope.clone(),
                issued_at: NOW,
                expires_at: Some(NOW + 1_000),
            },
            NOW,
        )
        .unwrap();

    let err = mesh
        .delegate(
            "tenant-a",
            DelegationRequest {
                id: DelegationId("delegation-too-wide".to_string()),
                delegator: manager.principal().id.clone(),
                delegate: invoice_agent.principal().id.clone(),
                capabilities: vec![capability("invoice.create")],
                resource_scope: ResourceScope::resource("invoice")
                    .with_attribute("department", ClaimValue::Enum("sales".to_string())),
                issued_at: NOW + 1,
                expires_at: Some(NOW + 1_000),
            },
            NOW + 1,
        )
        .unwrap_err();
    assert_eq!(err.denial, DenialReason::DelegationScopeDenied);

    let child = mesh
        .delegate(
            "tenant-a",
            DelegationRequest {
                id: DelegationId("delegation-invoice-agent".to_string()),
                delegator: manager.principal().id.clone(),
                delegate: invoice_agent.principal().id.clone(),
                capabilities: vec![capability("invoice.create")],
                resource_scope: parent_scope,
                issued_at: NOW + 1,
                expires_at: Some(NOW + 900),
            },
            NOW + 1,
        )
        .unwrap();
    assert_eq!(child.chain, vec![parent.id.clone()]);

    let context = mesh
        .session_context("tenant-a", &invoice_agent.session.id, NOW + 10)
        .unwrap();
    let decision = mesh.authorize(&context, &capability("invoice.create"), NOW + 10);
    let grant = decision.grant().unwrap();
    assert_eq!(
        grant.delegation_chain,
        vec![
            parent.id,
            DelegationId("delegation-invoice-agent".to_string())
        ]
    );
    assert_eq!(grant.principal_id, invoice_agent.principal().id);
    let evidence = mesh.recent_decisions().last().cloned().unwrap();
    assert_eq!(evidence.decision.as_str(), "allow");
    assert_eq!(evidence.delegation_chain, grant.delegation_chain);
    assert_eq!(evidence.delegated_by, Some(manager.principal().id.clone()));
}

#[test]
fn a_revoked_agent_loses_authority_independently_of_its_delegator() {
    let stores = MemoryStores::new();
    provision(&stores);
    let mesh = AuthMesh::new(config(), registry(), stores.mesh_stores()).expect("mesh builds");
    let (alice, agent, _bob) = sign_up_cast(&mesh);

    mesh.delegate(
        "tenant-a",
        DelegationRequest {
            id: DelegationId("delegation-invoices".to_string()),
            delegator: alice.principal().id.clone(),
            delegate: agent.principal().id.clone(),
            capabilities: vec![capability("invoice.create")],
            resource_scope: appport_auth_mesh_contract::ResourceScope::any(),
            issued_at: NOW,
            expires_at: Some(NOW + 1_000),
        },
        NOW,
    )
    .unwrap();

    let agent_context = mesh
        .session_context("tenant-a", &agent.session.id, NOW + 10)
        .unwrap();
    mesh.revoke_agent("tenant-a", &agent.principal().id, NOW + 20)
        .expect("the agent is revoked");

    // The delegation is still live, and Alice still holds the capability.
    let alice_context = mesh
        .session_context("tenant-a", &alice.session.id, NOW + 30)
        .unwrap();
    assert!(mesh
        .authorize(&alice_context, &capability("invoice.create"), NOW + 30)
        .is_allowed());

    // The agent has nothing, and cannot even open a new session.
    let revoked = mesh
        .principal(&tenant("tenant-a"), &agent.principal().id)
        .unwrap();
    let revoked_context = RuntimeContext {
        principal: revoked,
        ..agent_context
    };
    assert_denies(
        &mesh.authorize(&revoked_context, &capability("invoice.create"), NOW + 30),
        DenialReason::AgentRevoked,
    );
    assert_eq!(
        mesh.session_context("tenant-a", &agent.session.id, NOW + 30)
            .expect_err("a revoked agent has no context")
            .denial,
        DenialReason::AgentRevoked
    );
    assert_eq!(
        mesh.sign_in(
            "tenant-a",
            &credentials("tenant-a", "invoice-agent", "agent-secret"),
            NOW + 30
        )
        .expect_err("a revoked agent cannot sign in")
        .denial,
        DenialReason::AgentRevoked
    );
}

#[test]
fn tenant_isolation_holds_for_humans_and_for_agents() {
    let stores = MemoryStores::new();
    provision(&stores);
    let mesh = AuthMesh::new(config(), registry(), stores.mesh_stores()).expect("mesh builds");
    let (alice, agent, bob) = sign_up_cast(&mesh);

    mesh.delegate(
        "tenant-a",
        DelegationRequest {
            id: DelegationId("delegation-invoices".to_string()),
            delegator: alice.principal().id.clone(),
            delegate: agent.principal().id.clone(),
            capabilities: vec![capability("invoice.create")],
            resource_scope: appport_auth_mesh_contract::ResourceScope::any(),
            issued_at: NOW,
            expires_at: Some(NOW + 1_000),
        },
        NOW,
    )
    .unwrap();

    // Bob is in tenant B and cannot present his session to tenant A.
    assert_eq!(
        mesh.session_context("tenant-a", &bob.session.id, NOW + 10)
            .expect_err("cross-tenant session use is denied")
            .denial,
        DenialReason::TenantMismatch
    );
    assert!(!bob
        .context
        .capabilities
        .allows(&capability("reports.export")));

    // Neither can Alice's principal be read out of tenant B.
    assert_eq!(
        mesh.principal(&tenant("tenant-b"), &alice.principal().id)
            .expect_err("cross-tenant principal reads are denied")
            .denial,
        DenialReason::TenantMismatch
    );

    // An agent's delegated authority stops at its tenant boundary.
    let agent_context = mesh
        .session_context("tenant-a", &agent.session.id, NOW + 10)
        .unwrap();
    let cross_tenant = RuntimeContext {
        tenant: tenant("tenant-b"),
        ..agent_context
    };
    assert_denies(
        &mesh.authorize(&cross_tenant, &capability("invoice.create"), NOW + 10),
        DenialReason::TenantMismatch,
    );

    // Two tenants can hold the same connector subject without collision.
    let alice_b = mesh
        .sign_up(
            "tenant-b",
            &credentials("tenant-b", "alice", "alice-secret"),
            Registration::human()
                .with_claim("role", "member")
                .with_claim("plan", "free"),
            NOW,
        )
        .expect("the same external subject is a different principal in tenant B");
    assert_ne!(alice_b.principal().id, alice.principal().id);
}

#[test]
fn external_identities_resolve_deterministically_and_uniquely() {
    let stores = MemoryStores::new();
    provision(&stores);
    let mesh = AuthMesh::new(config(), registry(), stores.mesh_stores()).expect("mesh builds");
    let (alice, _agent, _bob) = sign_up_cast(&mesh);

    // (tenant, connector, external_subject) -> exactly one principal.
    let again = mesh
        .sign_in(
            "tenant-a",
            &credentials("tenant-a", "alice", "alice-secret"),
            NOW + 5,
        )
        .expect("Alice signs in again");
    assert_eq!(again.principal().id, alice.principal().id);
    assert_ne!(again.session.id, alice.session.id);

    assert_eq!(
        mesh.principal_id_for(&tenant("tenant-a"), "local", "alice"),
        alice.principal().id
    );

    // Registering the same external identity twice is refused.
    assert!(mesh
        .sign_up(
            "tenant-a",
            &credentials("tenant-a", "alice", "alice-secret"),
            Registration::human()
                .with_claim("role", "owner")
                .with_claim("plan", "pro"),
            NOW + 5,
        )
        .is_err());

    // Account linking: a second proven external identity, one principal.
    let linked = mesh
        .link_account(
            "tenant-a",
            &alice.principal().id,
            &credentials("tenant-a", "bob", "bob-secret"),
            NOW + 6,
        )
        .expect("Alice links a second external identity");
    assert_eq!(linked.principal_id, alice.principal().id);

    let via_link = mesh
        .sign_in(
            "tenant-a",
            &credentials("tenant-a", "bob", "bob-secret"),
            NOW + 7,
        )
        .expect("the linked identity signs in");
    assert_eq!(via_link.principal().id, alice.principal().id);

    // ... and that binding cannot be moved to another principal.
    let carol = mesh
        .sign_up(
            "tenant-a",
            &credentials("tenant-a", "carol", "carol-secret"),
            Registration::human()
                .with_claim("role", "member")
                .with_claim("plan", "free"),
            NOW + 8,
        )
        .unwrap();
    assert!(mesh
        .link_account(
            "tenant-a",
            &carol.principal().id,
            &credentials("tenant-a", "bob", "bob-secret"),
            NOW + 9,
        )
        .is_err());
}

#[test]
fn every_unresolved_input_is_denied() {
    let stores = MemoryStores::new();
    provision(&stores);
    let mesh = AuthMesh::new(config(), registry(), stores.mesh_stores()).expect("mesh builds");
    let (alice, _agent, _bob) = sign_up_cast(&mesh);

    let denial = |err: AuthError| err.denial;

    // Unknown tenant, and no implicit tenant.
    assert_eq!(
        denial(mesh.tenant("tenant-zzz").unwrap_err()),
        DenialReason::UnknownTenant
    );
    assert_eq!(
        denial(mesh.tenant("").unwrap_err()),
        DenialReason::UnknownTenant
    );

    // Unknown connector, and a connector the contract never declared.
    assert_eq!(
        denial(
            mesh.sign_in(
                "tenant-a",
                &AuthResponse {
                    connector: "google".to_string(),
                    ..AuthResponse::default()
                },
                NOW,
            )
            .unwrap_err()
        ),
        DenialReason::UnsupportedConnector
    );

    // Wrong credentials, and a challenge replayed into another tenant.
    assert!(mesh
        .sign_in(
            "tenant-a",
            &credentials("tenant-a", "alice", "not-the-password"),
            NOW,
        )
        .is_err());
    assert_eq!(
        denial(
            mesh.sign_in(
                "tenant-b",
                &credentials("tenant-a", "alice", "alice-secret"),
                NOW
            )
            .unwrap_err()
        ),
        DenialReason::TenantMismatch
    );

    // An unknown external identity is never provisioned on the way in.
    assert_eq!(
        denial(
            mesh.sign_in(
                "tenant-b",
                &credentials("tenant-b", "alice", "alice-secret"),
                NOW
            )
            .unwrap_err()
        ),
        DenialReason::UnknownPrincipal
    );

    // Invalid, expired and revoked sessions.
    assert_eq!(
        denial(
            mesh.session_context("tenant-a", &SessionId("session-999".to_string()), NOW)
                .unwrap_err()
        ),
        DenialReason::InvalidSession
    );
    assert_eq!(
        denial(
            mesh.session_context("tenant-a", &alice.session.id, NOW + 100_000)
                .unwrap_err()
        ),
        DenialReason::ExpiredSession
    );
    mesh.logout("tenant-a", &alice.session.id, NOW + 10)
        .unwrap();
    assert_eq!(
        denial(
            mesh.session_context("tenant-a", &alice.session.id, NOW + 20)
                .unwrap_err()
        ),
        DenialReason::RevokedSession
    );

    // A missing or undeclared claim is a denial, not a default.
    assert_eq!(
        denial(
            mesh.sign_up(
                "tenant-a",
                &credentials("tenant-a", "bob", "bob-secret"),
                Registration::human().with_claim("role", "admin"),
                NOW,
            )
            .unwrap_err()
        ),
        DenialReason::MissingClaim
    );
    assert_eq!(
        denial(
            mesh.sign_up(
                "tenant-a",
                &credentials("tenant-a", "bob", "bob-secret"),
                Registration::human()
                    .with_claim("role", "root")
                    .with_claim("plan", "pro"),
                NOW,
            )
            .unwrap_err()
        ),
        DenialReason::ClaimMismatch
    );

    // An unknown principal cannot be authorized, and an unknown capability is
    // not granted.
    let context = RuntimeContext {
        principal: Principal::human(
            PrincipalId("prn_nobody".to_string()),
            "tenant-a".into(),
            Claims {
                values: Default::default(),
            },
            appport_auth_mesh_runtime::resolution::CONTRACT_VERSION,
        ),
        tenant: tenant("tenant-a"),
        session_id: None,
        delegation: None,
        claims: Claims {
            values: Default::default(),
        },
        capabilities: CapabilityEnvelope::empty(),
    };
    assert_denies(
        &mesh.authorize(&context, &capability("invoice.create"), NOW),
        DenialReason::DelegationMissing,
    );
    assert_denies(
        &mesh.authorize(&context, &capability("nonsense.capability"), NOW),
        DenialReason::DelegationMissing,
    );
}

#[test]
fn agents_are_only_available_when_declared() {
    let stores = MemoryStores::new();
    provision(&stores);

    let config = parse_auth_block(
        r#"
use auth {
  providers = [local]
  tenant = true
  claims = {
    role = enum["owner", "admin", "member"]
    plan = enum["free", "pro"]
  }
}
"#,
    )
    .unwrap();
    let registry =
        ConnectorRegistry::from_config_with(&config, vec![Arc::new(directory())]).unwrap();
    let mesh = AuthMesh::new(config, registry, stores.mesh_stores()).expect("mesh builds");

    assert!(!mesh.surface().exposes("/auth/agents"));
    assert!(!mesh.surface().exposes("/auth/delegations"));

    let alice = mesh
        .sign_up(
            "tenant-a",
            &credentials("tenant-a", "alice", "alice-secret"),
            Registration::human()
                .with_claim("role", "admin")
                .with_claim("plan", "pro"),
            NOW,
        )
        .unwrap();

    assert!(mesh
        .sign_up(
            "tenant-a",
            &credentials("tenant-a", "invoice-agent", "agent-secret"),
            Registration::agent(),
            NOW,
        )
        .is_err());

    let err = mesh
        .delegate(
            "tenant-a",
            DelegationRequest {
                id: DelegationId("nope".to_string()),
                delegator: alice.principal().id.clone(),
                delegate: PrincipalId("prn_whoever".to_string()),
                capabilities: vec![capability("invoice.create")],
                resource_scope: appport_auth_mesh_contract::ResourceScope::any(),
                issued_at: NOW,
                expires_at: Some(NOW + 10),
            },
            NOW,
        )
        .unwrap_err();
    assert_eq!(err.denial, DenialReason::InvalidDelegation);
}

#[test]
fn an_unimplemented_connector_never_authenticates() {
    let stores = MemoryStores::new();
    provision(&stores);

    let config =
        parse_auth_block("use auth { providers = [local, google] tenant = true }").unwrap();
    let registry =
        ConnectorRegistry::from_config_with(&config, vec![Arc::new(directory())]).unwrap();
    let mesh = AuthMesh::new(config, registry, stores.mesh_stores()).expect("mesh builds");

    // Google is part of the contract and shows up in the surface...
    assert!(mesh.surface().provider("google").is_some());
    assert!(!mesh.surface().provider("google").unwrap().is_actionable());

    // ... but it cannot authenticate anyone.
    let err = mesh
        .sign_in(
            "tenant-a",
            &AuthResponse {
                connector: "google".to_string(),
                ..AuthResponse::default()
            },
            NOW,
        )
        .unwrap_err();
    assert_eq!(err.denial, DenialReason::UnsupportedConnector);
    assert!(err.message.contains("declared but not implemented"));

    let err = mesh
        .begin("tenant-a", &AuthRequest::new("google"))
        .unwrap_err();
    assert_eq!(err.denial, DenialReason::UnsupportedConnector);
}

#[test]
fn the_generated_contract_is_deterministic() {
    let stores = MemoryStores::new();
    provision(&stores);
    let mesh = AuthMesh::new(config(), registry(), stores.mesh_stores()).expect("mesh builds");

    let reordered = parse_auth_block(
        r#"
use auth {
  agents = true
  claims = {
    plan = enum["pro", "free"]
    role = enum["member", "admin", "owner"]
  }
  tenant = true
  providers = [local]
}
"#,
    )
    .unwrap();

    assert_eq!(config().fingerprint(), reordered.fingerprint());
    assert_eq!(
        mesh.surface().fingerprint(),
        AuthSurface::derive(&reordered).fingerprint()
    );
    assert_eq!(mesh.registry().ids(), vec!["local".to_string()]);
    assert_eq!(
        mesh.inspect(),
        appport_auth_mesh_surface::render_text(&AuthSurface::derive(&reordered))
    );
}

#[test]
fn a_delegation_belongs_to_one_tenant() {
    let stores = MemoryStores::new();
    provision(&stores);
    let mesh = AuthMesh::new(config(), registry(), stores.mesh_stores()).expect("mesh builds");
    let (alice, agent, _bob) = sign_up_cast(&mesh);

    // A delegation written against tenant B can never authorize in tenant A.
    let foreign = Delegation {
        id: DelegationId("foreign".to_string()),
        delegator: alice.principal().id.clone(),
        delegate: agent.principal().id.clone(),
        tenant_id: "tenant-b".into(),
        capabilities: vec![capability("invoice.create")],
        resource_scope: appport_auth_mesh_contract::ResourceScope::any(),
        issued_at: NOW,
        expires_at: Some(NOW + 1_000),
        revoked_at: None,
        chain: Vec::new(),
    };
    assert!(!foreign.is_valid_at(NOW + 2_000));

    let context = mesh
        .session_context("tenant-a", &agent.session.id, NOW + 10)
        .unwrap();
    let smuggled = RuntimeContext {
        delegation: Some(foreign),
        ..context
    };
    assert_denies(
        &mesh.authorize(&smuggled, &capability("invoice.create"), NOW + 10),
        DenialReason::DelegationMissing,
    );
}
