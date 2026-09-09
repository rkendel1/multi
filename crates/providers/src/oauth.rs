use crate::{ProviderError, ProviderIdentity};

pub struct OauthProvider;

impl OauthProvider {
    pub fn authenticate(_token: &str, provider: &str) -> Result<ProviderIdentity, ProviderError> {
        Err(ProviderError::Unsupported {
            provider: provider.to_string(),
        })
    }
}
