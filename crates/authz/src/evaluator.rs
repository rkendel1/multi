use appport_auth_mesh_contract::{Identity, TenantContext};

use crate::policy::{CapabilityEnvelope, Condition, Policy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluationError {
    pub message: String,
}

impl std::fmt::Display for PolicyEvaluationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PolicyEvaluationError {}

pub fn evaluate(
    policy: &Policy,
    identity: &Identity,
    tenant: &TenantContext,
) -> Result<CapabilityEnvelope, PolicyEvaluationError> {
    if identity.tenant_id != tenant.tenant_id {
        return Err(PolicyEvaluationError {
            message: "identity tenant does not match tenant context".to_string(),
        });
    }

    if policy.id != tenant.policy_id {
        return Err(PolicyEvaluationError {
            message: "policy does not match tenant context".to_string(),
        });
    }

    let mut granted_capabilities = Vec::new();

    for rule in &policy.rules {
        if condition_matches(&rule.condition, identity) {
            granted_capabilities.push(rule.capability.clone());
        }
    }

    Ok(CapabilityEnvelope {
        granted_capabilities,
    })
}

fn condition_matches(condition: &Condition, identity: &Identity) -> bool {
    match condition {
        Condition::ClaimEquals { key, value } => identity.claims.values.get(key) == Some(value),
        Condition::ClaimIn { key, values } => identity
            .claims
            .values
            .get(key)
            .map(|v| values.contains(v))
            .unwrap_or(false),
        Condition::TimeBound { start, end } => {
            let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(v) => v.as_secs() as i64,
                Err(_) => return false,
            };
            now >= *start && now <= *end
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use appport_auth_mesh_contract::{
        ClaimValue, Claims, ContractVersion, Identity, OfflineSemantics, TenantContext,
    };

    use crate::{
        evaluator::evaluate,
        policy::{Condition, Policy, Rule},
    };

    #[test]
    fn grants_capability_when_claim_matches() {
        let mut claims = HashMap::new();
        claims.insert("role".to_string(), ClaimValue::Enum("admin".to_string()));
        let identity = Identity {
            id: "id-1".to_string(),
            provider: "local".to_string(),
            tenant_id: "tenant-a".to_string(),
            claims: Claims { values: claims },
            version: ContractVersion { major: 1, minor: 0 },
            offline: OfflineSemantics {
                max_age_seconds: 300,
                must_revalidate: false,
            },
        };
        let tenant = TenantContext {
            tenant_id: "tenant-a".to_string(),
            namespace: "tenant-a".to_string(),
            policy_id: "p1".to_string(),
            storage_root_id: "root-a".to_string(),
        };
        let policy = Policy {
            id: "p1".to_string(),
            rules: vec![Rule {
                capability: "billing.charge".to_string(),
                condition: Condition::ClaimEquals {
                    key: "role".to_string(),
                    value: ClaimValue::Enum("admin".to_string()),
                },
            }],
        };

        let envelope = evaluate(&policy, &identity, &tenant).expect("policy should evaluate");
        assert_eq!(envelope.granted_capabilities, vec!["billing.charge"]);
    }

    #[test]
    fn fails_closed_when_identity_tenant_does_not_match_context() {
        let identity = Identity {
            id: "id-1".to_string(),
            provider: "local".to_string(),
            tenant_id: "tenant-a".to_string(),
            claims: Claims {
                values: HashMap::new(),
            },
            version: ContractVersion { major: 1, minor: 0 },
            offline: OfflineSemantics {
                max_age_seconds: 300,
                must_revalidate: false,
            },
        };
        let tenant = TenantContext {
            tenant_id: "tenant-b".to_string(),
            namespace: "tenant-b".to_string(),
            policy_id: "p1".to_string(),
            storage_root_id: "root-b".to_string(),
        };
        let policy = Policy {
            id: "p1".to_string(),
            rules: vec![Rule {
                capability: "storage.read".to_string(),
                condition: Condition::TimeBound {
                    start: 0,
                    end: i64::MAX,
                },
            }],
        };

        let err = evaluate(&policy, &identity, &tenant).expect_err("tenant mismatch must fail");
        assert_eq!(err.message, "identity tenant does not match tenant context");
    }
}
