//! A small SaaS application, as AuthPort intends one to be written.
//!
//! The application declares identity and authority in `appport.auth` and then
//! states its policy. It never declares a user table, a session table, token
//! storage, callback plumbing, tenant lookup or auth middleware.
//!
//! ```text
//! Tenant A                       Tenant B
//!   Alice   (human)                Bob (human)
//!   Invoice Agent (agent)
//! ```

use std::sync::Arc;

use appport_auth_mesh_authz::{AuthorizationDecision, Condition, Policy, Rule};
use appport_auth_mesh_contract::{Capability, ClaimValue, DelegationId, TenantContext};
use appport_auth_mesh_dsl::parse_auth_block;
use appport_auth_mesh_providers::{
    AuthConnector, AuthRequest, AuthResponse, ConnectorRegistry, LocalAccount, LocalConnector,
};
use appport_auth_mesh_runtime::{
    AuthError, AuthMesh, DelegationRequest, MemoryPolicyStore, MeshStores, Registration,
    RuntimeContext,
};
use appport_auth_mesh_storage::memory::{
    MemoryAuditLog, MemoryDelegationStore, MemoryIdentityStore, MemoryPrincipalStore,
    MemorySessionStore, MemoryTenantRoot,
};
use appport_auth_mesh_storage::TenantRootStore;

/// The application's auth declaration.
const DECLARATION: &str = include_str!("../appport.auth");

const NOW: i64 = 1_000;

fn main() {
    match run() {
        Ok(report) => print!("{}", report),
        Err(err) => {
            eprintln!("saas_basic: {} ({:?})", err.message, err.stage);
            std::process::exit(1);
        }
    }
}

fn run() -> Result<String, AuthError> {
    let config = parse_auth_block(DECLARATION).expect("the declaration is valid");

    // The only auth code the application writes: its accounts directory and
    // its policy. Everything else is derived.
    let directory = LocalConnector::new()
        .with_account(LocalAccount::new("alice", "alice-secret"))
        .with_account(LocalAccount::new("invoice-agent", "agent-secret"))
        .with_account(LocalAccount::new("bob", "bob-secret"));
    let registry = ConnectorRegistry::from_config_with(&config, vec![Arc::new(directory)])
        .expect("connectors resolve from the declaration");

    let tenants = MemoryTenantRoot::new();
    let identities = MemoryIdentityStore::new();
    let principals = MemoryPrincipalStore::new();
    let sessions = MemorySessionStore::new();
    let delegations = MemoryDelegationStore::new();
    let policies = MemoryPolicyStore::new();
    let audit = MemoryAuditLog::new();

    let acme = tenant("acme");
    let globex = tenant("globex");
    for tenant in [&acme, &globex] {
        tenants.put_tenant(tenant.clone()).expect("tenant root");
        policies.put(policy(tenant)).expect("tenant policy");
    }

    let mesh = AuthMesh::new(
        config,
        registry,
        MeshStores {
            tenants: &tenants,
            identities: &identities,
            principals: &principals,
            sessions: &sessions,
            delegations: &delegations,
            policies: &policies,
            audit: &audit,
        },
    )?;

    let mut report = String::new();
    report.push_str(&mesh.inspect());
    report.push('\n');

    // ── Alice: a human in tenant A ──────────────────────────────────────────
    let alice = mesh.sign_up(
        "acme",
        &credentials("acme", "alice", "alice-secret"),
        Registration::human()
            .with_claim("role", "admin")
            .with_claim("plan", "pro"),
        NOW,
    )?;
    let alice_context = mesh.session_context("acme", &alice.session.id, NOW)?;

    report.push_str("Alice\n");
    report.push_str(&format!("  authenticated:  {}\n", check(true)));
    report.push_str(&format!(
        "  principal:      {}\n",
        alice_context.principal.id
    ));
    report.push_str(&format!(
        "  tenant:         {}\n",
        alice_context.tenant.tenant_id
    ));
    report.push_str(&format!(
        "  role:           {}\n",
        claim(&alice_context, "role")
    ));
    report.push_str(&format!(
        "  invoice.create: {}\n",
        outcome(&mesh.authorize(&alice_context, &capability("invoice.create"), NOW))
    ));
    report.push_str(&format!(
        "  billing.charge: {}\n\n",
        outcome(&mesh.authorize(&alice_context, &capability("billing.charge"), NOW))
    ));

    // ── The invoice agent: an agent in tenant A, not a user with a role ──────
    let agent = mesh.sign_up(
        "acme",
        &credentials("acme", "invoice-agent", "agent-secret"),
        Registration::agent(),
        NOW,
    )?;

    let before_delegation = mesh.session_context("acme", &agent.session.id, NOW)?;
    let denied_before = mesh.authorize(&before_delegation, &capability("invoice.create"), NOW);

    let delegation = mesh.delegate(
        "acme",
        DelegationRequest {
            id: DelegationId("delegation-invoices".to_string()),
            delegator: alice.principal().id.clone(),
            delegate: agent.principal().id.clone(),
            capabilities: vec![capability("invoice.create")],
            issued_at: NOW,
            expires_at: NOW + 3_600,
        },
        NOW,
    )?;

    let agent_context = mesh.session_context("acme", &agent.session.id, NOW)?;
    let allowed = mesh.authorize(&agent_context, &capability("invoice.create"), NOW);

    report.push_str("Invoice Agent\n");
    report.push_str(&format!("  authenticated:  {}\n", check(true)));
    report.push_str(&format!(
        "  principal:      {}\n",
        agent_context.principal.id
    ));
    report.push_str(&format!(
        "  distinct:       {}\n",
        check(agent_context.principal.id != alice_context.principal.id)
    ));
    report.push_str(&format!(
        "  tenant:         {}\n",
        agent_context.tenant.tenant_id
    ));
    report.push_str(&format!("  before grant:   {}\n", outcome(&denied_before)));
    report.push_str(&format!("  invoice.create: {}\n", outcome(&allowed)));
    report.push_str(&format!(
        "  reports.export: {}\n",
        outcome(&mesh.authorize(&agent_context, &capability("reports.export"), NOW))
    ));
    if let Some(grant) = allowed.grant() {
        report.push_str("\n  why:\n");
        for line in grant.explain().lines() {
            report.push_str(&format!("    {}\n", line));
        }
    }
    report.push('\n');

    // ── Bob: a human in tenant B ────────────────────────────────────────────
    let bob = mesh.sign_up(
        "globex",
        &credentials("globex", "bob", "bob-secret"),
        Registration::human()
            .with_claim("role", "owner")
            .with_claim("plan", "free"),
        NOW,
    )?;
    let cross_tenant = mesh.session_context("acme", &bob.session.id, NOW);

    report.push_str("Bob\n");
    report.push_str(&format!("  authenticated:  {}\n", check(true)));
    report.push_str(&format!(
        "  tenant:         {}\n",
        bob.context.tenant.tenant_id
    ));
    report.push_str(&format!(
        "  tenant acme:    {}\n\n",
        match &cross_tenant {
            Ok(_) => "ALLOW".to_string(),
            Err(err) => format!("DENY ({})", err.denial.as_str()),
        }
    ));

    // ── Revocation ──────────────────────────────────────────────────────────
    mesh.revoke_delegation("acme", &delegation.id, NOW + 60)?;
    let after_revocation = mesh.session_context("acme", &agent.session.id, NOW + 120)?;

    report.push_str("Revocation\n");
    report.push_str(&format!(
        "  agent invoice.create: {}\n",
        outcome(&mesh.authorize(&after_revocation, &capability("invoice.create"), NOW + 120))
    ));
    report.push_str(&format!(
        "  alice invoice.create: {}\n",
        outcome(&mesh.authorize(
            &mesh.session_context("acme", &alice.session.id, NOW + 120)?,
            &capability("invoice.create"),
            NOW + 120
        ))
    ));
    report.push_str(&format!(
        "  audit events:         {}\n",
        audit.events().map(|events| events.len()).unwrap_or(0)
    ));

    Ok(report)
}

fn tenant(id: &str) -> TenantContext {
    TenantContext {
        tenant_id: id.into(),
        namespace: id.to_string(),
        policy_id: format!("{}-policy", id).into(),
        storage_root_id: format!("{}-root", id).into(),
    }
}

/// What the application authorizes, in its own vocabulary.
fn policy(tenant: &TenantContext) -> Policy {
    Policy {
        id: tenant.policy_id.clone(),
        rules: vec![
            Rule {
                capability: capability("invoice.create"),
                condition: Condition::ClaimIn {
                    key: "role".to_string(),
                    values: vec![
                        ClaimValue::Enum("owner".to_string()),
                        ClaimValue::Enum("admin".to_string()),
                    ],
                },
            },
            Rule {
                capability: capability("reports.export"),
                condition: Condition::ClaimEquals {
                    key: "plan".to_string(),
                    value: ClaimValue::Enum("pro".to_string()),
                },
            },
            Rule {
                capability: capability("billing.charge"),
                condition: Condition::ClaimEquals {
                    key: "role".to_string(),
                    value: ClaimValue::Enum("owner".to_string()),
                },
            },
        ],
    }
}

fn credentials(tenant_id: &str, username: &str, password: &str) -> AuthResponse {
    let connector = LocalConnector::new();
    let challenge = connector
        .begin(
            &AuthRequest::new("local")
                .for_tenant(tenant_id)
                .with_parameter("username", username),
        )
        .expect("the local connector issues a challenge");

    AuthResponse::to_challenge(&challenge)
        .for_tenant(tenant_id)
        .with_parameter("username", username)
        .with_parameter("password", password)
}

fn capability(name: &str) -> Capability {
    Capability(name.to_string())
}

fn claim(context: &RuntimeContext, name: &str) -> String {
    match context.claims.values.get(name) {
        Some(ClaimValue::Enum(value)) | Some(ClaimValue::String(value)) => value.clone(),
        Some(ClaimValue::Integer(value)) => value.to_string(),
        Some(ClaimValue::Boolean(value)) => value.to_string(),
        None => "(none)".to_string(),
    }
}

fn outcome(decision: &AuthorizationDecision) -> String {
    match decision {
        AuthorizationDecision::Allow { grant, .. } => {
            if grant.is_delegated() {
                format!("{} (delegated)", check(true))
            } else {
                check(true).to_string()
            }
        }
        AuthorizationDecision::Deny { reason, .. } => format!("DENY ({})", reason.as_str()),
    }
}

fn check(value: bool) -> &'static str {
    if value {
        "✓"
    } else {
        "✗"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_example_demonstrates_humans_agents_delegation_and_isolation() {
        let report = run().expect("the example runs");

        // The declaration generated the surface.
        assert!(report.contains("Multi-tenant: yes"));
        assert!(report.contains("/auth/delegations"));

        // Alice is an admin in tenant A and can create invoices, but she is not
        // an owner, so billing stays closed to her.
        assert!(report.contains("Alice\n  authenticated:  ✓"));
        assert!(report.contains("  role:           admin"));
        assert!(report.contains("  invoice.create: ✓"));
        assert!(report.contains("  billing.charge: DENY (capability_not_granted)"));

        // The agent is a distinct principal and holds nothing until Alice
        // delegates; then it holds exactly what she delegated.
        assert!(report.contains("  distinct:       ✓"));
        assert!(report.contains("  before grant:   DENY (capability_not_granted)"));
        assert!(report.contains("  invoice.create: ✓ (delegated)"));
        assert!(report.contains("  reports.export: DENY (capability_not_granted)"));
        assert!(report.contains("authority: delegated"));

        // Bob cannot reach tenant A.
        assert!(report.contains("  tenant acme:    DENY (tenant_mismatch)"));

        // Revocation removes the agent's authority, not Alice's.
        assert!(report.contains("  agent invoice.create: DENY (revoked_delegation)"));
        assert!(report.contains("  alice invoice.create: ✓"));
    }
}
