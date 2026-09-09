use crate::{ProviderError, ProviderIdentity};

pub struct MagicLinkProvider;

impl MagicLinkProvider {
    pub fn authenticate(token: &str) -> Result<ProviderIdentity, ProviderError> {
        let _ = token;
        Err(ProviderError::Unsupported {
            provider: "magic_link".to_string(),
        })
    }
}
