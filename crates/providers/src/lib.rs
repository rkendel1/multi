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
