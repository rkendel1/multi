use crate::{ProviderError, ProviderIdentity};

pub struct JwtProvider;

impl JwtProvider {
    pub fn authenticate(jwt: &str) -> Result<ProviderIdentity, ProviderError> {
        let _ = jwt;
        Err(ProviderError::Unsupported {
            provider: "jwt".to_string(),
        })
    }
}
