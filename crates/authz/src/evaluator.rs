use appport_auth_mesh_contract::{Identity, Tenant};

use crate::policy::{CapabilityEnvelope, Condition, Policy};

pub fn evaluate(policy: &Policy, identity: &Identity, _tenant: &Tenant) -> CapabilityEnvelope {
    let mut granted_capabilities = Vec::new();

    for rule in &policy.rules {
        if condition_matches(&rule.condition, identity) {
            granted_capabilities.push(rule.capability.clone());
        }
    }

    CapabilityEnvelope {
        granted_capabilities,
    }
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
        ClaimValue, Claims, ContractVersion, Identity, OfflineSemantics, Tenant,
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
        let tenant = Tenant {
            id: "tenant-a".to_string(),
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

        let envelope = evaluate(&policy, &identity, &tenant);
        assert_eq!(envelope.granted_capabilities, vec!["billing.charge"]);
    }
}
