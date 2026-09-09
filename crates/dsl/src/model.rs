use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    pub multi_tenant: bool,
    pub providers: Vec<String>,
    pub claims: Vec<ClaimDef>,
    pub isolation: IsolationMode,
}

impl AuthConfig {
    pub fn canonical(&self) -> Self {
        let mut providers = self.providers.clone();
        providers.sort();

        let mut claims = self.claims.clone();
        claims.sort_by(|a, b| a.name.cmp(&b.name));
        for claim in &mut claims {
            if let ClaimKind::Enum(values) = &mut claim.kind {
                values.sort();
            }
        }

        Self {
            multi_tenant: self.multi_tenant,
            providers,
            claims,
            isolation: self.isolation.clone(),
        }
    }

    pub fn fingerprint(&self) -> String {
        let canonical = self.canonical();
        let mut bytes = Vec::new();
        canonical.write_canonical(&mut bytes);
        format!("{:016x}", stable_hash(&bytes))
    }

    pub fn validate(&self) -> Result<(), AuthConfigError> {
        if self.providers.is_empty() {
            return Err(AuthConfigError {
                message: "missing providers".to_string(),
            });
        }

        reject_duplicates(&self.providers, "duplicate provider")?;

        let mut claim_names = HashSet::new();
        for claim in &self.claims {
            if claim.name.trim().is_empty() {
                return Err(AuthConfigError {
                    message: "claim name cannot be empty".to_string(),
                });
            }
            if !claim_names.insert(claim.name.clone()) {
                return Err(AuthConfigError {
                    message: format!("duplicate claim `{}`", claim.name),
                });
            }
            if let ClaimKind::Enum(values) = &claim.kind {
                if values.is_empty() {
                    return Err(AuthConfigError {
                        message: format!("enum claim `{}` must have values", claim.name),
                    });
                }
                reject_duplicates(values, "duplicate enum value")?;
            }
        }

        Ok(())
    }

    fn write_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(format!("multi_tenant={};", self.multi_tenant).as_bytes());
        out.extend_from_slice(b"providers=");
        for provider in &self.providers {
            out.extend_from_slice(provider.as_bytes());
            out.push(b',');
        }
        out.extend_from_slice(format!(";isolation={:?};claims=", self.isolation).as_bytes());
        for claim in &self.claims {
            out.extend_from_slice(claim.name.as_bytes());
            out.push(b':');
            match &claim.kind {
                ClaimKind::Enum(values) => {
                    out.extend_from_slice(b"enum[");
                    for value in values {
                        out.extend_from_slice(value.as_bytes());
                        out.push(b',');
                    }
                    out.push(b']');
                }
                ClaimKind::String => out.extend_from_slice(b"string"),
                ClaimKind::Integer => out.extend_from_slice(b"integer"),
                ClaimKind::Boolean => out.extend_from_slice(b"boolean"),
            }
            out.push(b';');
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfigError {
    pub message: String,
}

impl std::fmt::Display for AuthConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AuthConfigError {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClaimDef {
    pub name: String,
    pub kind: ClaimKind,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClaimKind {
    Enum(Vec<String>),
    String,
    Integer,
    Boolean,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationMode {
    Strict,
    SharedStorageWithPolicy,
}

fn reject_duplicates(values: &[String], message: &str) -> Result<(), AuthConfigError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(AuthConfigError {
                message: format!("{} `{}`", message, value),
            });
        }
    }
    Ok(())
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
