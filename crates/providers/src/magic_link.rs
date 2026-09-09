use crate::{ProviderError, ProviderIdentity};

pub struct MagicLinkProvider;

impl MagicLinkProvider {
    pub fn authenticate(token: &str) -> Result<ProviderIdentity, ProviderError> {
        if token.trim().is_empty() {
            return Err(ProviderError {
                message: "magic link token cannot be empty".to_string(),
            });
        }

        Ok(ProviderIdentity {
            provider: "magic_link".to_string(),
            subject: token.to_string(),
        })
    }
}
