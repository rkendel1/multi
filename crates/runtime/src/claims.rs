use std::collections::BTreeMap;

use appport_auth_mesh_authz::DenialReason;
use appport_auth_mesh_contract::{ClaimValue, Claims};
use appport_auth_mesh_dsl::{AuthConfig, ClaimKind};

use crate::error::{AuthError, AuthLifecycleStage};

/// Claims are resolved against the declared schema, never trusted as given.
///
/// A declared claim that is absent is a denial, and an enum claim only accepts
/// the variants the contract lists.
pub fn resolve_claims(
    config: &AuthConfig,
    provided: &BTreeMap<String, String>,
) -> Result<Claims, AuthError> {
    let mut values = std::collections::HashMap::new();
    for claim in &config.claims {
        let raw = provided
            .get(&claim.name)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AuthError::new(
                    AuthLifecycleStage::ClaimsResolution,
                    format!("missing required claim `{}`", claim.name),
                    DenialReason::MissingClaim,
                )
            })?;
        values.insert(claim.name.clone(), parse_claim_value(&claim.kind, raw)?);
    }

    for name in provided.keys() {
        if config.claim(name).is_none() {
            return Err(AuthError::new(
                AuthLifecycleStage::ClaimsResolution,
                format!("undeclared claim `{}`", name),
                DenialReason::ClaimMismatch,
            ));
        }
    }

    Ok(Claims { values })
}

pub fn parse_claim_value(kind: &ClaimKind, raw: &str) -> Result<ClaimValue, AuthError> {
    match kind {
        ClaimKind::Enum(allowed) => {
            if allowed.iter().any(|value| value == raw) {
                Ok(ClaimValue::Enum(raw.to_string()))
            } else {
                Err(claim_error("claim value is not allowed"))
            }
        }
        ClaimKind::String => Ok(ClaimValue::String(raw.to_string())),
        ClaimKind::Integer => raw
            .parse::<i64>()
            .map(ClaimValue::Integer)
            .map_err(|_| claim_error("claim value is not an integer")),
        ClaimKind::Boolean => match raw {
            "true" => Ok(ClaimValue::Boolean(true)),
            "false" => Ok(ClaimValue::Boolean(false)),
            _ => Err(claim_error("claim value is not a boolean")),
        },
    }
}

fn claim_error(message: &str) -> AuthError {
    AuthError::new(
        AuthLifecycleStage::ClaimsResolution,
        message,
        DenialReason::ClaimMismatch,
    )
}
