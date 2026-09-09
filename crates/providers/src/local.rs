use crate::{ProviderError, ProviderIdentity};

pub struct LocalProvider;

impl LocalProvider {
    pub fn authenticate(creds: LocalCredentials) -> Result<ProviderIdentity, ProviderError> {
        if creds.username.trim().is_empty() || creds.password.is_empty() {
            return Err(ProviderError::InvalidCredentials {
                message: "invalid local credentials".to_string(),
            });
        }

        Ok(ProviderIdentity {
            provider: "local".to_string(),
            subject: creds.username,
        })
    }
}

pub struct LocalCredentials {
    pub username: String,
    pub password: String,
}
