use crate::{ProviderError, ProviderIdentity};

pub struct OauthProvider;

impl OauthProvider {
    pub fn authenticate(token: &str, provider: &str) -> Result<ProviderIdentity, ProviderError> {
        if token.trim().is_empty() {
            return Err(ProviderError {
                message: "oauth token cannot be empty".to_string(),
            });
        }
        if provider.trim().is_empty() {
            return Err(ProviderError {
                message: "oauth provider cannot be empty".to_string(),
            });
        }

        Ok(ProviderIdentity {
            provider: provider.to_string(),
            subject: token.to_string(),
        })
    }
}
