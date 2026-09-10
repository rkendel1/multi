use std::collections::HashMap;

use appport_auth_mesh_contract::{
    AuditEventId, DelegationId, PrincipalId, RunId, SessionId, TenantContext, TenantId,
};

use crate::StorageError;

pub trait AuditLog {
    fn record_event(&self, tenant: &TenantContext, event: AuditEvent) -> Result<(), StorageError>;

    fn events(
        &self,
        _tenant: &TenantContext,
        _since: Option<i64>,
        _limit: usize,
    ) -> Result<Vec<AuditEvent>, StorageError> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub event_id: AuditEventId,
    pub tenant_id: TenantId,
    pub principal_id: Option<PrincipalId>,
    pub delegator_id: Option<PrincipalId>,
    pub session_id: Option<SessionId>,
    pub delegation_id: Option<DelegationId>,
    pub run_id: Option<RunId>,
    pub kind: AuditEventKind,
    pub timestamp: i64,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub decision: Option<String>,
    pub reason: Option<String>,
    pub authority_revision: Option<u64>,
    pub contract_fingerprint: Option<String>,
    pub durability: AuditDurability,
    pub metadata: HashMap<String, String>,
}

impl AuditEvent {
    pub fn canonical_json_line(&self) -> String {
        let mut fields = vec![
            ("id", json_string(self.event_id.as_str())),
            ("timestamp", self.timestamp.to_string()),
            ("tenant", json_string(self.tenant_id.as_str())),
            ("kind", json_string(self.kind.as_str())),
            ("durability", json_string(self.durability.as_str())),
        ];
        fields.push((
            "principal",
            optional_json_string(self.principal_id.as_ref().map(|id| id.as_str())),
        ));
        fields.push((
            "delegator",
            optional_json_string(self.delegator_id.as_ref().map(|id| id.as_str())),
        ));
        fields.push((
            "session_id",
            optional_json_string(self.session_id.as_ref().map(|id| id.as_str())),
        ));
        fields.push((
            "delegation_id",
            optional_json_string(self.delegation_id.as_ref().map(|id| id.as_str())),
        ));
        fields.push((
            "run_id",
            optional_json_string(self.run_id.as_ref().map(|id| id.as_str())),
        ));
        fields.push(("action", optional_json_string(self.action.as_deref())));
        fields.push(("resource", optional_json_string(self.resource.as_deref())));
        fields.push(("decision", optional_json_string(self.decision.as_deref())));
        fields.push(("reason", optional_json_string(self.reason.as_deref())));
        fields.push((
            "authority_revision",
            self.authority_revision
                .map(|revision| revision.to_string())
                .unwrap_or_else(|| "null".to_string()),
        ));
        fields.push((
            "contract_fingerprint",
            optional_json_string(self.contract_fingerprint.as_deref()),
        ));

        let mut metadata = self.metadata.iter().collect::<Vec<_>>();
        metadata.sort_by(|a, b| a.0.cmp(b.0));
        let metadata = metadata
            .into_iter()
            .map(|(key, value)| format!("{}:{}", json_string(key), json_string(value)))
            .collect::<Vec<_>>()
            .join(",");
        fields.push(("metadata", format!("{{{}}}", metadata)));

        format!(
            "{{{}}}",
            fields
                .into_iter()
                .map(|(key, value)| format!("{}:{}", json_string(key), value))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEventKind {
    Login,
    Logout,
    SessionCreated,
    SessionRevoked,
    AccountLinked,
    ClaimsUpdated,
    AuthorizationGranted,
    AuthorizationDenied,
    DelegationCreated,
    DelegationRevoked,
    AgentCreated,
    AgentSuspended,
    AgentRevoked,
    AgentRunCreated,
    AgentRunCancelled,
}

impl AuditEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "authentication.login",
            Self::Logout => "authentication.logout",
            Self::SessionCreated => "session.created",
            Self::SessionRevoked => "session.revoked",
            Self::AccountLinked => "identity.account_linked",
            Self::ClaimsUpdated => "identity.claims_updated",
            Self::AuthorizationGranted => "authorization.granted",
            Self::AuthorizationDenied => "authorization.denied",
            Self::DelegationCreated => "delegation.created",
            Self::DelegationRevoked => "delegation.revoked",
            Self::AgentCreated => "agent.created",
            Self::AgentSuspended => "agent.suspended",
            Self::AgentRevoked => "agent.revoked",
            Self::AgentRunCreated => "run.created",
            Self::AgentRunCancelled => "run.cancelled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditDurability {
    Required,
    BestEffort,
    Optional,
}

impl AuditDurability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::BestEffort => "best_effort",
            Self::Optional => "optional",
        }
    }
}

pub trait AuditSink {
    fn publish(&self, event: &AuditEvent) -> Result<(), StorageError>;
}

pub fn export_json_lines(events: &[AuditEvent]) -> String {
    let mut out = events
        .iter()
        .map(AuditEvent::canonical_json_line)
        .collect::<Vec<_>>()
        .join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

fn optional_json_string(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_string())
}

fn json_string(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .chars()
            .flat_map(|ch| match ch {
                '\\' => "\\\\".chars().collect::<Vec<_>>(),
                '"' => "\\\"".chars().collect(),
                '\n' => "\\n".chars().collect(),
                '\r' => "\\r".chars().collect(),
                '\t' => "\\t".chars().collect(),
                ch => vec![ch],
            })
            .collect::<String>()
    )
}
