//! Wiring AuthPort into the application — the whole of it.
//!
//! A declaration, a directory of accounts, a policy, and the tenants the
//! application serves. There is no authentication code below this file.

use std::sync::Arc;

use appport_auth_mesh_authz::{Condition, Policy, Rule};
use appport_auth_mesh_boundary::{
    AuthPortRuntime, BindingMode, Clock, RegistrationPolicy, SystemClock, TestClock,
};
use appport_auth_mesh_contract::{
    Capability, ClaimValue, DelegationId, PrincipalId, TenantContext,
};
use appport_auth_mesh_dsl::{parse_auth_block, AuthConfig};
use appport_auth_mesh_providers::{
    AuthConnector, AuthRequest, AuthResponse, ConnectorRegistry, LocalAccount, LocalConnector,
};
use appport_auth_mesh_runtime::{AuthError, DelegationRequest, MemoryStores, Registration};
use appport_auth_mesh_storage::TenantRootStore;

use crate::app::Invoices;

/// The application's auth declaration. One file, one contract.
pub const DECLARATION: &str = include_str!("../appport.auth");

pub const START: i64 = 1_000;
pub const SESSION_TTL: i64 = 3_600;

pub struct Deployment {
    pub runtime: Arc<AuthPortRuntime>,
    pub stores: MemoryStores,
    pub clock: Arc<dyn Clock>,
    /// Present only when the deployment runs on a controllable clock, which is
    /// how expiry is exercised without waiting for it.
    pub controls: Option<Arc<TestClock>>,
    pub invoices: Arc<Invoices>,
    pub alice: PrincipalId,
    pub bob: PrincipalId,
    pub agent: PrincipalId,
    pub delegation: DelegationId,
}

impl Deployment {
    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    /// Move time forward, where the deployment's clock allows it.
    pub fn advance(&self, seconds: i64) {
        if let Some(controls) = &self.controls {
            controls.advance(seconds);
        }
    }
}

pub fn contract() -> AuthConfig {
    parse_auth_block(DECLARATION).expect("the declaration is valid")
}

/// The accounts the local connector knows. In production this is an identity
/// provider; here it is deterministic so the whole flow is testable.
pub fn directory() -> LocalConnector {
    LocalConnector::new()
        .with_account(
            LocalAccount::new("alice", "alice-secret").with_attribute("email", "alice@acme.test"),
        )
        .with_account(LocalAccount::new("invoice-agent", "agent-secret"))
        .with_account(LocalAccount::new("bob", "bob-secret"))
}

/// What the application authorizes, in its own vocabulary.
pub fn policy(tenant: &TenantContext) -> Policy {
    Policy {
        id: tenant.policy_id.clone(),
        rules: vec![
            Rule::allow(
                Capability("invoice.read".to_string()),
                Condition::ClaimIn {
                    key: "role".to_string(),
                    values: vec![
                        ClaimValue::Enum("owner".to_string()),
                        ClaimValue::Enum("admin".to_string()),
                        ClaimValue::Enum("member".to_string()),
                    ],
                },
            ),
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
            // Owning the account is not the same as being able to spend money.
            Rule::allow(
                Capability("billing.charge".to_string()),
                Condition::ClaimEquals {
                    key: "billing".to_string(),
                    value: ClaimValue::Enum("manager".to_string()),
                },
            ),
        ],
    }
}

pub fn tenant(id: &str) -> TenantContext {
    TenantContext {
        tenant_id: id.into(),
        namespace: id.to_string(),
        policy_id: format!("{}-policy", id).into(),
        storage_root_id: format!("{}-root", id).into(),
    }
}

/// Credentials as a caller would submit them.
pub fn credentials(tenant_id: &str, username: &str, password: &str) -> AuthResponse {
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

/// A deployment on a controllable clock, for the demo and the tests.
pub fn bootstrap(mode: BindingMode) -> Result<Deployment, AuthError> {
    bootstrap_with(mode, Arc::new(TestClock::new(START)))
}

/// A deployment on the system clock, for actually running the application.
pub fn bootstrap_live(mode: BindingMode) -> Result<Deployment, AuthError> {
    build(mode, Arc::new(SystemClock), None, MemoryStores::new())
}

/// Build the runtime and seed the cast.
///
/// The same function serves both binding modes: only the mode tag differs, so
/// the two deployments cannot diverge in what they permit.
pub fn bootstrap_with(mode: BindingMode, clock: Arc<TestClock>) -> Result<Deployment, AuthError> {
    bootstrap_with_stores(mode, clock, MemoryStores::new())
}

/// The same wiring against caller-supplied state — used to prove what happens
/// when part of that state (the audit log, say) stops working.
pub fn bootstrap_with_stores(
    mode: BindingMode,
    clock: Arc<TestClock>,
    stores: MemoryStores,
) -> Result<Deployment, AuthError> {
    build(mode, clock.clone(), Some(clock), stores)
}

fn build(
    mode: BindingMode,
    clock: Arc<dyn Clock>,
    controls: Option<Arc<TestClock>>,
    stores: MemoryStores,
) -> Result<Deployment, AuthError> {
    let config = contract();
    let registry = ConnectorRegistry::from_config_with(&config, vec![Arc::new(directory())])
        .expect("connectors resolve from the declaration");

    let acme = tenant("acme");
    let globex = tenant("globex");
    for tenant in [&acme, &globex] {
        stores
            .tenants
            .put_tenant(tenant.clone())
            .expect("tenant root");
        stores.policies.put(policy(tenant)).expect("tenant policy");
    }

    let runtime = AuthPortRuntime::new(config, registry, stores.mesh_stores(), mode)?
        .with_clock(clock.clone())
        .with_session_ttl(SESSION_TTL)
        // Self-service registration is closed: principals are provisioned by
        // the application, so nobody can register themselves a role.
        .with_registration(RegistrationPolicy::Closed);

    let now = clock.now();
    let mesh = runtime.mesh();

    let alice = mesh
        .sign_up(
            "acme",
            &credentials("acme", "alice", "alice-secret"),
            Registration::human()
                .with_claim("role", "owner")
                .with_claim("plan", "pro")
                .with_claim("billing", "none"),
            now,
        )?
        .principal()
        .id
        .clone();

    let bob = mesh
        .sign_up(
            "globex",
            &credentials("globex", "bob", "bob-secret"),
            Registration::human()
                .with_claim("role", "owner")
                .with_claim("plan", "free")
                .with_claim("billing", "none"),
            now,
        )?
        .principal()
        .id
        .clone();

    // Alice creates the invoice agent. It is a principal of its own, not a
    // user with a role.
    let agent = mesh
        .sign_up(
            "acme",
            &credentials("acme", "invoice-agent", "agent-secret"),
            Registration::agent(),
            now,
        )?
        .principal()
        .id
        .clone();

    // ... and delegates part of her own authority to it.
    let delegation = mesh
        .delegate(
            "acme",
            DelegationRequest {
                id: DelegationId("delegation-invoices".to_string()),
                delegator: alice.clone(),
                delegate: agent.clone(),
                capabilities: vec![
                    Capability("invoice.read".to_string()),
                    Capability("invoice.create".to_string()),
                ],
                resource_scope: appport_auth_mesh_contract::ResourceScope::resource("invoice"),
                issued_at: now,
                expires_at: Some(now + 3_600),
            },
            now,
        )?
        .id;

    Ok(Deployment {
        runtime: Arc::new(runtime),
        stores,
        clock,
        controls,
        invoices: Arc::new(Invoices::default()),
        alice,
        bob,
        agent,
        delegation,
    })
}
