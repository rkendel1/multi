pub mod jwt;
pub mod local;
pub mod magic_link;
pub mod oauth;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIdentity {
    pub provider: String,
    pub subject: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    InvalidCredentials { message: String },
    Unsupported { provider: String },
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCredentials { message } => write!(f, "{}", message),
            Self::Unsupported { provider } => write!(f, "provider `{}` is contract only", provider),
        }
    }
}

impl std::error::Error for ProviderError {}

#[cfg(test)]
mod tests {
    use crate::jwt::JwtProvider;
    use crate::local::{LocalCredentials, LocalProvider};
    use crate::magic_link::MagicLinkProvider;
    use crate::oauth::OauthProvider;
    use crate::ProviderError;

    #[test]
    fn local_provider_authenticates_concrete_credentials() {
        let identity = LocalProvider::authenticate(LocalCredentials {
            username: "alice".to_string(),
            password: "not-empty".to_string(),
        })
        .expect("local provider is implemented");

        assert_eq!(identity.provider, "local");
        assert_eq!(identity.subject, "alice");
    }

    #[test]
    fn contract_only_providers_fail_as_unsupported() {
        assert_eq!(
            OauthProvider::authenticate("token", "oauth").unwrap_err(),
            ProviderError::Unsupported {
                provider: "oauth".to_string()
            }
        );
        assert_eq!(
            JwtProvider::authenticate("jwt").unwrap_err(),
            ProviderError::Unsupported {
                provider: "jwt".to_string()
            }
        );
        assert_eq!(
            MagicLinkProvider::authenticate("token").unwrap_err(),
            ProviderError::Unsupported {
                provider: "magic_link".to_string()
            }
        );
    }
}
