use crate::model::{AuthConfig, ClaimDef, ClaimKind, IsolationMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDslError {
    pub message: String,
}

impl std::fmt::Display for AuthDslError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AuthDslError {}

pub fn parse_auth_block(src: &str) -> Result<AuthConfig, AuthDslError> {
    if src.matches("use auth").count() > 1 {
        return Err(AuthDslError {
            message: "multiple auth blocks are not allowed".to_string(),
        });
    }

    let block = extract_auth_block(src)?;

    let mut multi_tenant = None;
    let mut providers = None;
    let mut claims = Vec::new();
    let mut isolation = None;

    let mut lines = block.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed == "}" || trimmed == "{" {
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("multi_tenant:") {
            let v = value.trim();
            multi_tenant = Some(match v {
                "true" => true,
                "false" => false,
                _ => {
                    return Err(AuthDslError {
                        message: "multi_tenant must be true or false".to_string(),
                    })
                }
            });
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("providers:") {
            providers = Some(parse_providers(value.trim())?);
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("isolation:") {
            isolation = Some(parse_isolation(value.trim())?);
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("claims:") {
            let mut claims_block = value.trim().to_string();
            if !claims_block.contains('}') {
                while let Some(next_line) = lines.next() {
                    claims_block.push('\n');
                    claims_block.push_str(next_line.trim());
                    if next_line.contains('}') {
                        break;
                    }
                }
            }
            claims = parse_claims(&claims_block)?;
            continue;
        }

        return Err(AuthDslError {
            message: format!("unknown auth field `{}`", trimmed),
        });
    }

    let config = AuthConfig {
        multi_tenant: multi_tenant.ok_or_else(|| AuthDslError {
            message: "missing multi_tenant".to_string(),
        })?,
        providers: providers.ok_or_else(|| AuthDslError {
            message: "missing providers".to_string(),
        })?,
        claims,
        isolation: isolation.ok_or_else(|| AuthDslError {
            message: "missing isolation".to_string(),
        })?,
    };
    config.validate().map_err(|err| AuthDslError { message: err.message })?;
    Ok(config)
}

fn extract_auth_block(src: &str) -> Result<String, AuthDslError> {
    let start = src.find("use auth").ok_or_else(|| AuthDslError {
        message: "missing `use auth` block".to_string(),
    })?;
    let open = src[start..].find('{').ok_or_else(|| AuthDslError {
        message: "missing `{` in auth block".to_string(),
    })? + start;

    let mut depth = 0usize;
    let mut close = None;
    for (idx, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + idx);
                    break;
                }
            }
            _ => {}
        }
    }

    let close = close.ok_or_else(|| AuthDslError {
        message: "missing closing `}` in auth block".to_string(),
    })?;

    Ok(src[open + 1..close].to_string())
}

fn parse_providers(input: &str) -> Result<Vec<String>, AuthDslError> {
    if !(input.starts_with('[') && input.ends_with(']')) {
        return Err(AuthDslError {
            message: "providers must be in []".to_string(),
        });
    }

    let inner = &input[1..input.len() - 1];
    let items = inner
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    if items.is_empty() {
        return Err(AuthDslError {
            message: "providers cannot be empty".to_string(),
        });
    }

    Ok(items)
}

fn parse_isolation(input: &str) -> Result<IsolationMode, AuthDslError> {
    let normalized = input.trim_matches('"').to_ascii_lowercase();
    match normalized.as_str() {
        "strict" => Ok(IsolationMode::Strict),
        "shared_storage_with_policy" => Ok(IsolationMode::SharedStorageWithPolicy),
        _ => Err(AuthDslError {
            message: format!("unknown isolation mode `{}`", input),
        }),
    }
}

fn parse_claims(input: &str) -> Result<Vec<ClaimDef>, AuthDslError> {
    let open = input.find('{').ok_or_else(|| AuthDslError {
        message: "claims must start with `{`".to_string(),
    })?;
    let close = input.rfind('}').ok_or_else(|| AuthDslError {
        message: "claims must end with `}`".to_string(),
    })?;

    let body = &input[open + 1..close];
    let mut out = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        if trimmed.is_empty() {
            continue;
        }
        let (name, raw_kind) = trimmed.split_once(':').ok_or_else(|| AuthDslError {
            message: format!("invalid claim definition `{}`", trimmed),
        })?;
        out.push(ClaimDef {
            name: name.trim().to_string(),
            kind: parse_claim_kind(raw_kind.trim())?,
        });
    }
    Ok(out)
}

fn parse_claim_kind(input: &str) -> Result<ClaimKind, AuthDslError> {
    if let Some(raw) = input.strip_prefix("enum[").and_then(|s| s.strip_suffix(']')) {
        let variants = raw
            .split(',')
            .map(|s| s.trim().trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        if variants.is_empty() {
            return Err(AuthDslError {
                message: "enum claim must have values".to_string(),
            });
        }
        let mut seen = std::collections::HashSet::new();
        for variant in &variants {
            if !seen.insert(variant) {
                return Err(AuthDslError {
                    message: format!("duplicate enum value `{}`", variant),
                });
            }
        }
        return Ok(ClaimKind::Enum(variants));
    }

    match input {
        "string" => Ok(ClaimKind::String),
        "integer" => Ok(ClaimKind::Integer),
        "boolean" => Ok(ClaimKind::Boolean),
        _ => Err(AuthDslError {
            message: format!("unsupported claim kind `{}`", input),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mvp_auth_block() {
        let src = r#"
use auth {
  multi_tenant: true
  providers: [local, google, microsoft]
  claims: {
    role: enum["admin","user"]
    plan: enum["free","pro"]
  }
  isolation: "strict"
}
"#;

        let parsed = parse_auth_block(src).expect("parser should parse valid DSL");
        assert!(parsed.multi_tenant);
        assert_eq!(parsed.providers, vec!["local", "google", "microsoft"]);
        assert_eq!(parsed.claims.len(), 2);
        assert_eq!(parsed.isolation, IsolationMode::Strict);
    }
}
