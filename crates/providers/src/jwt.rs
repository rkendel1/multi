use crate::{ProviderError, ProviderIdentity};

pub struct JwtProvider;

impl JwtProvider {
    pub fn authenticate(jwt: &str) -> Result<ProviderIdentity, ProviderError> {
        if jwt.trim().is_empty() {
            return Err(ProviderError {
                message: "jwt cannot be empty".to_string(),
            });
        }

        Ok(ProviderIdentity {
            provider: "jwt".to_string(),
            subject: jwt.to_string(),
        })
    }
}
