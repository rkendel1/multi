use std::collections::HashMap;

use appport_auth_mesh_authz::{
    evaluate_capability, AuthorizationDecision, Condition, DenialReason, Policy, Rule,
};
use appport_auth_mesh_contract::{
    AgentState, Capability, ClaimValue, Claims, ContractVersion, Delegation, DelegationId,
    Principal, PrincipalId, PrincipalKind, ProviderName, ProviderSubject, StorageRootId,
    TenantContext,
};
use appport_auth_mesh_dsl::parse_auth_block;
use appport_auth_mesh_storage::audit_log::{AuditEvent, AuditEventKind, AuditLog};
use appport_auth_mesh_storage::delegation_store::DelegationStore;
use appport_auth_mesh_storage::identity_store::IdentityStore;
use appport_auth_mesh_storage::memory::{
    audit_event_id, MemoryAuditLog, MemoryDelegationStore, MemoryIdentityStore,
    MemoryPrincipalStore, MemorySessionStore, MemoryTenantRoot,
};
use appport_auth_mesh_storage::principal_store::PrincipalStore;
use appport_auth_mesh_storage::session_store::SessionStore;
use appport_auth_mesh_storage::tenant_root::TenantRootStore;

fn tenant(id: &str) -> TenantContext {
    TenantContext {
        tenant_id: id.into(),
        namespace: id.to_string(),
        policy_id: format!("{}-policy", id).into(),
        storage_root_id: format!("{}-root", id).into(),
    }
}

fn claims(role: &str, plan: &str) -> Claims {
    let mut values = HashMap::new();
    values.insert("role".to_string(), ClaimValue::Enum(role.to_string()));
    values.insert("plan".to_string(), ClaimValue::Enum(plan.to_string()));
    Claims { values }
}

fn principal(id: &str, kind: PrincipalKind, tenant: &TenantContext, claims: Claims) -> Principal {
    Principal {
        id: PrincipalId(id.to_string()),
        kind,
        tenant_id: tenant.tenant_id.clone(),
        claims,
        version: ContractVersion { major: 1, minor: 0 },
        agent_state: None,
    }
}

fn active_agent(id: &str, tenant: &TenantContext) -> Principal {
    let mut agent = principal(
        id,
        PrincipalKind::Agent,
        tenant,
        Claims {
            values: HashMap::new(),
        },
    );
    agent.agent_state = Some(AgentState::Active);
    agent
}

fn policy(tenant: &TenantContext) -> Policy {
    Policy {
        id: tenant.policy_id.clone(),
        rules: vec![
            Rule::allow(
                Capability("billing.charge".to_string()),
                Condition::ClaimEquals {
                    key: "role".to_string(),
                    value: ClaimValue::Enum("admin".to_string()),
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
                Capability("invoice.create".to_string()),
                Condition::ClaimEquals {
                    key: "role".to_string(),
                    value: ClaimValue::Enum("admin".to_string()),
                },
            ),
        ],
    }
}

fn assert_allow(decision: AuthorizationDecision, capability: &str) {
    match decision {
        AuthorizationDecision::Allow { grant, .. } => {
            assert_eq!(grant.capability, Capability(capability.to_string()));
            assert!(!grant.claim_basis.is_empty());
        }
        AuthorizationDecision::Deny { reason, .. } => {
            panic!("expected allow, got deny: {reason:?}");
        }
    }
}

fn assert_deny(decision: AuthorizationDecision, expected: DenialReason) {
    match decision {
        AuthorizationDecision::Allow { grant, .. } => {
            panic!("expected deny, got allow: {grant:?}");
        }
        AuthorizationDecision::Deny { reason, .. } => assert_eq!(reason, expected),
    }
}

#[test]
fn humans_agents_delegation_and_tenant_boundaries_work_end_to_end() {
    let dsl = r#"
use auth {
  multi_tenant: true
  providers: [local, agent]
  claims: {
    role: enum["admin","user"]
    plan: enum["free","pro"]
  }
  isolation: "strict"
}
"#;
    let auth_config = parse_auth_block(dsl).expect("valid auth DSL");
    assert_eq!(
        auth_config.fingerprint(),
        parse_auth_block(dsl).unwrap().canonical().fingerprint()
    );

    let tenant_a = tenant("tenant-a");
    let tenant_b = tenant("tenant-b");
    let tenant_roots = MemoryTenantRoot::new();
    tenant_roots.put_tenant(tenant_a.clone()).unwrap();
    tenant_roots.put_tenant(tenant_b.clone()).unwrap();
    tenant_roots
        .verify_storage_root(&tenant_a, &StorageRootId("tenant-a-root".to_string()))
        .unwrap();
    assert!(tenant_roots
        .verify_storage_root(&tenant_a, &StorageRootId("tenant-b-root".to_string()))
        .is_err());

    let identities = MemoryIdentityStore::new();
    let alice_identity = identities
        .link_account(
            &tenant_a,
            &ProviderName("local".to_string()),
            &ProviderSubject("alice".to_string()),
        )
        .unwrap();
    assert!(identities
        .link_account(
            &tenant_a,
            &ProviderName("local".to_string()),
            &ProviderSubject("alice".to_string()),
        )
        .is_err());
    assert!(identities
        .get_identity(&tenant_b, &alice_identity.id)
        .is_err());

    let principals = MemoryPrincipalStore::new();
    let alice = principal(
        "alice",
        PrincipalKind::Human,
        &tenant_a,
        claims("admin", "pro"),
    );
    let invoice_agent = active_agent("invoice-agent", &tenant_a);
    let tenant_b_agent = active_agent("tenant-b-agent", &tenant_b);
    principals.put_principal(alice.clone()).unwrap();
    principals.put_principal(invoice_agent.clone()).unwrap();
    principals.put_principal(tenant_b_agent.clone()).unwrap();

    let sessions = MemorySessionStore::new();
    let session = sessions
        .create_session(&tenant_a, &alice_identity.id, 100, None)
        .unwrap();
    sessions
        .validate_session(&tenant_a, &session.id, 50)
        .expect("active session is valid");
    assert!(sessions
        .validate_session(&tenant_b, &session.id, 50)
        .is_err());
    assert!(sessions
        .validate_session(&tenant_a, &session.id, 100)
        .is_err());

    let policy = policy(&tenant_a);
    assert_allow(
        evaluate_capability(
            Some(&policy),
            Some(&alice),
            Some(&tenant_a),
            None,
            &Capability("billing.charge".to_string()),
            10,
        ),
        "billing.charge",
    );
    assert_allow(
        evaluate_capability(
            Some(&policy),
            Some(&alice),
            Some(&tenant_a),
            None,
            &Capability("reports.export".to_string()),
            10,
        ),
        "reports.export",
    );

    let delegations = MemoryDelegationStore::new();
    let delegation = delegations
        .create_delegation(Delegation {
            id: DelegationId("delegation-1".to_string()),
            delegator: alice.id.clone(),
            delegate: invoice_agent.id.clone(),
            tenant_id: tenant_a.tenant_id.clone(),
            capabilities: vec![
                Capability("invoice.create".to_string()),
                Capability("invoice.read".to_string()),
            ],
            resource_scope: appport_auth_mesh_contract::ResourceScope::any(),
            issued_at: 0,
            expires_at: Some(100),
            revoked_at: None,
            chain: Vec::new(),
        })
        .unwrap();

    assert_allow(
        evaluate_capability(
            Some(&policy),
            Some(&invoice_agent),
            Some(&tenant_a),
            Some(&delegation),
            &Capability("invoice.create".to_string()),
            10,
        ),
        "invoice.create",
    );
    assert_allow(
        evaluate_capability(
            Some(&policy),
            Some(&invoice_agent),
            Some(&tenant_a),
            Some(&delegation),
            &Capability("invoice.read".to_string()),
            10,
        ),
        "invoice.read",
    );
    assert_deny(
        evaluate_capability(
            Some(&policy),
            Some(&invoice_agent),
            Some(&tenant_a),
            Some(&delegation),
            &Capability("billing.charge".to_string()),
            10,
        ),
        DenialReason::DelegationMissing,
    );
    assert_deny(
        evaluate_capability(
            Some(&policy),
            Some(&invoice_agent),
            Some(&tenant_a),
            Some(&delegation),
            &Capability("reports.export".to_string()),
            10,
        ),
        DenialReason::DelegationMissing,
    );

    assert_allow(
        evaluate_capability(
            Some(&policy),
            Some(&alice),
            Some(&tenant_a),
            None,
            &Capability("invoice.create".to_string()),
            10,
        ),
        "invoice.create",
    );

    delegations
        .revoke_delegation(&tenant_a, &delegation.id, 20)
        .unwrap();
    let revoked_delegation = delegations
        .get_delegation(&tenant_a, &delegation.id)
        .unwrap()
        .unwrap();
    assert_deny(
        evaluate_capability(
            Some(&policy),
            Some(&invoice_agent),
            Some(&tenant_a),
            Some(&revoked_delegation),
            &Capability("invoice.create".to_string()),
            30,
        ),
        DenialReason::RevokedDelegation,
    );

    principals
        .set_agent_state(&tenant_a, &invoice_agent.id, AgentState::Revoked)
        .unwrap();
    let revoked_agent = principals
        .get_principal(&tenant_a, &invoice_agent.id)
        .unwrap()
        .unwrap();
    assert_deny(
        evaluate_capability(
            Some(&policy),
            Some(&revoked_agent),
            Some(&tenant_a),
            Some(&revoked_delegation),
            &Capability("invoice.read".to_string()),
            30,
        ),
        DenialReason::AgentRevoked,
    );

    assert_deny(
        evaluate_capability(
            Some(&policy),
            Some(&tenant_b_agent),
            Some(&tenant_a),
            None,
            &Capability("invoice.read".to_string()),
            10,
        ),
        DenialReason::TenantMismatch,
    );

    let audit = MemoryAuditLog::new();
    audit
        .record_event(
            &tenant_a,
            AuditEvent {
                event_id: audit_event_id("deny-1"),
                tenant_id: tenant_a.tenant_id.clone(),
                principal_id: Some(invoice_agent.id.clone()),
                session_id: None,
                delegation_id: Some(delegation.id.clone()),
                kind: AuditEventKind::AuthorizationDenied,
                timestamp: 30,
                metadata: HashMap::from([("reason".to_string(), "RevokedDelegation".to_string())]),
            },
        )
        .unwrap();
    assert_eq!(audit.events().unwrap().len(), 1);
}

#[test]
fn adversarial_authorization_cases_fail_closed() {
    let tenant_a = tenant("tenant-a");
    let tenant_b = tenant("tenant-b");
    let alice = principal(
        "alice",
        PrincipalKind::Human,
        &tenant_a,
        claims("admin", "pro"),
    );
    let agent = active_agent("agent", &tenant_a);
    let policy = policy(&tenant_a);

    assert_deny(
        evaluate_capability(
            None,
            Some(&alice),
            Some(&tenant_a),
            None,
            &Capability("billing.charge".to_string()),
            10,
        ),
        DenialReason::PolicyNotFound,
    );
    assert_deny(
        evaluate_capability(
            Some(&policy),
            None,
            Some(&tenant_a),
            None,
            &Capability("billing.charge".to_string()),
            10,
        ),
        DenialReason::UnknownPrincipal,
    );
    assert_deny(
        evaluate_capability(
            Some(&policy),
            Some(&alice),
            None,
            None,
            &Capability("billing.charge".to_string()),
            10,
        ),
        DenialReason::UnknownTenant,
    );
    assert_deny(
        evaluate_capability(
            Some(&policy),
            Some(&alice),
            Some(&tenant_b),
            None,
            &Capability("billing.charge".to_string()),
            10,
        ),
        DenialReason::TenantMismatch,
    );
    assert_deny(
        evaluate_capability(
            Some(&policy),
            Some(&agent),
            Some(&tenant_a),
            Some(&Delegation {
                id: DelegationId("expired".to_string()),
                delegator: alice.id.clone(),
                delegate: agent.id.clone(),
                tenant_id: tenant_a.tenant_id.clone(),
                capabilities: vec![Capability("invoice.create".to_string())],
                resource_scope: appport_auth_mesh_contract::ResourceScope::any(),
                issued_at: 0,
                expires_at: Some(5),
                revoked_at: None,
                chain: Vec::new(),
            }),
            &Capability("invoice.create".to_string()),
            10,
        ),
        DenialReason::ExpiredDelegation,
    );
    assert_deny(
        evaluate_capability(
            Some(&policy),
            Some(&agent),
            Some(&tenant_a),
            Some(&Delegation {
                id: DelegationId("wrong-tenant".to_string()),
                delegator: alice.id.clone(),
                delegate: agent.id.clone(),
                tenant_id: tenant_b.tenant_id.clone(),
                capabilities: vec![Capability("invoice.create".to_string())],
                resource_scope: appport_auth_mesh_contract::ResourceScope::any(),
                issued_at: 0,
                expires_at: Some(100),
                revoked_at: None,
                chain: Vec::new(),
            }),
            &Capability("invoice.create".to_string()),
            10,
        ),
        DenialReason::InvalidDelegation,
    );
}
