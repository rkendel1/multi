//! `authport serve` — run AuthPort as its own authority service.
//!
//! The deployment details a contract does not own (which tenants exist, which
//! accounts the local directory holds, what the policy grants, where the
//! application is) come from flags. The authority model is the same one an
//! embedded deployment uses.

use std::collections::BTreeMap;
use std::sync::Arc;

use appport_auth_mesh_authz::{Condition, Policy, Rule};
use appport_auth_mesh_boundary::{AuthPortRuntime, BindingMode, Method, Requirement};
use appport_auth_mesh_contract::{Capability, ClaimValue, TenantContext};
use appport_auth_mesh_dsl::AuthConfig;
use appport_auth_mesh_providers::{ConnectorRegistry, LocalAccount, LocalConnector};
use appport_auth_mesh_runtime::{MemoryStores, Registration};
use appport_auth_mesh_server::{
    serve, AuthPortServer, PathPattern, RoutePolicy, ServerHandle, UpstreamProxy,
};
use appport_auth_mesh_storage::TenantRootStore;

use crate::{error, CliError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeOptions {
    pub address: String,
    pub tenants: Vec<String>,
    pub accounts: Vec<Account>,
    pub grants: Vec<Grant>,
    pub upstream: Option<String>,
    pub public_paths: Vec<String>,
    pub required: Vec<(String, String)>,
    pub proxy_secret: String,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:8787".to_string(),
            tenants: Vec::new(),
            accounts: Vec::new(),
            grants: Vec::new(),
            upstream: None,
            public_paths: Vec::new(),
            required: Vec::new(),
            proxy_secret: "authport-development-secret".to_string(),
        }
    }
}

/// `--account alice:secret:role=owner,plan=pro@acme`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub tenant: String,
    pub username: String,
    pub password: String,
    pub claims: BTreeMap<String, String>,
}

impl Account {
    pub fn parse(raw: &str, default_tenant: &str) -> Result<Self, CliError> {
        let (spec, tenant) = match raw.rsplit_once('@') {
            Some((spec, tenant)) => (spec, tenant.to_string()),
            None => (raw, default_tenant.to_string()),
        };

        let mut parts = spec.splitn(3, ':');
        let username = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| error("--account needs a username"))?
            .to_string();
        let password = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| error(format!("--account {} needs a password", username)))?
            .to_string();
        let claims = parts
            .next()
            .map(|claims| {
                claims
                    .split(',')
                    .filter(|claim| !claim.trim().is_empty())
                    .filter_map(|claim| claim.split_once('='))
                    .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            tenant,
            username,
            password,
            claims,
        })
    }
}

/// `--grant invoice.read=role:owner`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub capability: String,
    pub claim: String,
    pub value: String,
}

impl Grant {
    pub fn parse(raw: &str) -> Result<Self, CliError> {
        let (capability, condition) = raw
            .split_once('=')
            .ok_or_else(|| error("--grant expects capability=claim:value"))?;
        let (claim, value) = condition
            .split_once(':')
            .ok_or_else(|| error("--grant expects capability=claim:value"))?;
        Ok(Self {
            capability: capability.trim().to_string(),
            claim: claim.trim().to_string(),
            value: value.trim().to_string(),
        })
    }
}

pub struct RunningServer {
    pub authport: ServerHandle,
    pub upstream: Option<String>,
    pub tenants: Vec<String>,
}

/// Build and start the standalone runtime.
pub fn start(config: AuthConfig, options: &ServeOptions) -> Result<RunningServer, CliError> {
    let tenants = if options.tenants.is_empty() {
        vec!["default".to_string()]
    } else {
        options.tenants.clone()
    };

    let mut directory = LocalConnector::new();
    for account in &options.accounts {
        directory
            .register(LocalAccount::new(
                account.username.clone(),
                account.password.clone(),
            ))
            .map_err(|err| error(err.to_string()))?;
    }

    let registry = ConnectorRegistry::from_config_with(&config, vec![Arc::new(directory)])
        .map_err(|err| error(format!("connector registry: {}", err)))?;

    let stores = MemoryStores::new();
    for tenant in &tenants {
        let context = tenant_context(tenant);
        stores
            .tenants
            .put_tenant(context.clone())
            .map_err(|err| error(err.message))?;
        stores
            .policies
            .put(policy(&context, &options.grants))
            .map_err(|err| error(err.message))?;
    }

    let runtime = AuthPortRuntime::new(
        config,
        registry,
        stores.mesh_stores(),
        BindingMode::Standalone,
    )
    .map_err(|err| error(err.message))?;

    // Accounts become principals up front: registration stays closed, so
    // nobody can grant themselves claims over HTTP.
    let now = runtime.now();
    for account in &options.accounts {
        let mut registration = Registration::human();
        registration.claims = account.claims.clone();
        runtime
            .mesh()
            .sign_up(
                &account.tenant,
                &crate::serve::credentials(&account.tenant, &account.username, &account.password),
                registration,
                now,
            )
            .map_err(|err| {
                error(format!(
                    "seeding account `{}`: {}",
                    account.username, err.message
                ))
            })?;
    }

    let runtime = Arc::new(runtime);
    let tenant_names: Vec<&str> = tenants.iter().map(String::as_str).collect();

    let server = match &options.upstream {
        Some(upstream) => {
            let address = upstream
                .parse()
                .map_err(|_| error(format!("invalid --upstream address `{}`", upstream)))?;
            let proxy = UpstreamProxy::new(
                address,
                application_policy(options),
                options.proxy_secret.clone(),
            );
            AuthPortServer::new(runtime, Arc::new(proxy)).with_tenants(&tenant_names)
        }
        // With no application behind it, AuthPort still serves its own surface:
        // sign-in, session, providers and authorization.
        None => AuthPortServer::new(runtime, Arc::new(AuthOnly)).with_tenants(&tenant_names),
    };

    let handle = serve(Arc::new(server), options.address.as_str())
        .map_err(|err| error(format!("cannot bind {}: {}", options.address, err)))?;

    Ok(RunningServer {
        authport: handle,
        upstream: options.upstream.clone(),
        tenants,
    })
}

/// The requirement table for a proxied application: explicit public paths,
/// explicit capability requirements, and authentication for everything else
/// that is listed. Nothing unlisted is forwarded.
fn application_policy(options: &ServeOptions) -> RoutePolicy {
    let all = [
        Method::Get,
        Method::Post,
        Method::Put,
        Method::Patch,
        Method::Delete,
        Method::Head,
    ];

    let mut policy = RoutePolicy::new();
    for path in &options.public_paths {
        policy = policy.rule(&all, PathPattern::Prefix(path.clone()), Requirement::Public);
    }
    for (path, capability) in &options.required {
        policy = policy.rule(
            &all,
            PathPattern::Prefix(path.clone()),
            Requirement::capability(capability),
        );
    }
    policy.rule(
        &all,
        PathPattern::Prefix("/".to_string()),
        Requirement::Authenticated,
    )
}

fn tenant_context(tenant: &str) -> TenantContext {
    TenantContext {
        tenant_id: tenant.into(),
        namespace: tenant.to_string(),
        policy_id: format!("{}-policy", tenant).into(),
        storage_root_id: format!("{}-root", tenant).into(),
    }
}

fn policy(tenant: &TenantContext, grants: &[Grant]) -> Policy {
    Policy {
        id: tenant.policy_id.clone(),
        rules: grants
            .iter()
            .map(|grant| Rule {
                capability: Capability(grant.capability.clone()),
                condition: Condition::ClaimEquals {
                    key: grant.claim.clone(),
                    value: ClaimValue::Enum(grant.value.clone()),
                },
            })
            .collect(),
    }
}

pub(crate) fn credentials(
    tenant: &str,
    username: &str,
    password: &str,
) -> appport_auth_mesh_providers::AuthResponse {
    use appport_auth_mesh_providers::{AuthConnector, AuthRequest, AuthResponse};

    let connector = LocalConnector::new();
    let challenge = connector
        .begin(
            &AuthRequest::new("local")
                .for_tenant(tenant)
                .with_parameter("username", username),
        )
        .expect("the local connector issues a challenge");

    AuthResponse::to_challenge(&challenge)
        .for_tenant(tenant)
        .with_parameter("username", username)
        .with_parameter("password", password)
}

/// A deployment with no application behind it.
struct AuthOnly;

impl appport_auth_mesh_server::ApplicationBinding for AuthOnly {
    fn resolve(&self, _method: Method, _path: &str) -> appport_auth_mesh_server::RouteOutcome {
        appport_auth_mesh_server::RouteOutcome::NotFound
    }

    fn handle(
        &self,
        _request: &appport_auth_mesh_boundary::BoundaryRequest,
        _context: Option<&appport_auth_mesh_boundary::AuthContext>,
    ) -> appport_auth_mesh_server::HttpResponse {
        appport_auth_mesh_server::HttpResponse::denied(
            404,
            "no_application",
            "this AuthPort deployment serves the auth surface only",
        )
    }
}
