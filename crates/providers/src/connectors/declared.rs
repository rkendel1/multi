use crate::catalog;
use crate::connector::{
    AuthChallenge, AuthConnector, AuthRequest, AuthResponse, ConnectorError, ConnectorMetadata,
    ExternalIdentity,
};

/// A connector the contract declares but the platform has not implemented.
///
/// It exists so the contract, the registry and the generated surface can all
/// name it honestly. Every attempt to authenticate through it is refused: a
/// declared connector is never a fallback.
pub struct DeclaredConnector {
    metadata: ConnectorMetadata,
}

impl DeclaredConnector {
    pub fn new(id: &str) -> Self {
        Self {
            metadata: catalog::describe(id),
        }
    }

    fn unsupported(&self) -> ConnectorError {
        ConnectorError::Unsupported {
            connector: self.metadata.id.clone(),
        }
    }
}

impl AuthConnector for DeclaredConnector {
    fn id(&self) -> &str {
        &self.metadata.id
    }

    fn metadata(&self) -> ConnectorMetadata {
        self.metadata.clone()
    }

    fn begin(&self, _request: &AuthRequest) -> Result<AuthChallenge, ConnectorError> {
        Err(self.unsupported())
    }

    fn authenticate(&self, _response: &AuthResponse) -> Result<ExternalIdentity, ConnectorError> {
        Err(self.unsupported())
    }
}
