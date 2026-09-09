use std::collections::BTreeMap;
use std::sync::Arc;

use appport_auth_mesh_dsl::AuthConfig;

use crate::catalog;
use crate::connector::{AuthConnector, ConnectorError, ConnectorMetadata, ConnectorStatus};
use crate::connectors::{DeclaredConnector, LocalConnector};

/// Resolves the connector names in `providers = [...]` to connector instances.
///
/// The runtime authenticates through the registry, never through a hard-coded
/// provider match, so a new connector is a registration rather than a change to
/// the authentication flow.
#[derive(Clone, Default)]
pub struct ConnectorRegistry {
    connectors: BTreeMap<String, Arc<dyn AuthConnector>>,
}

impl ConnectorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, connector: Arc<dyn AuthConnector>) -> Result<(), ConnectorError> {
        let id = connector.id().to_string();
        if self.connectors.contains_key(&id) {
            return Err(ConnectorError::DuplicateConnector { connector: id });
        }
        self.connectors.insert(id, connector);
        Ok(())
    }

    /// Build the registry the contract asks for, using the built-in connector
    /// for every declared provider.
    pub fn from_config(config: &AuthConfig) -> Result<Self, ConnectorError> {
        Self::from_config_with(config, Vec::new())
    }

    /// Same, but the application supplies configured instances (for example a
    /// local directory with accounts). An override for a connector the contract
    /// does not declare is refused: the declaration is authoritative.
    pub fn from_config_with(
        config: &AuthConfig,
        overrides: Vec<Arc<dyn AuthConnector>>,
    ) -> Result<Self, ConnectorError> {
        let mut registry = Self::new();

        let mut supplied: BTreeMap<String, Arc<dyn AuthConnector>> = BTreeMap::new();
        for connector in overrides {
            let id = connector.id().to_string();
            if !config.declares_provider(&id) {
                return Err(ConnectorError::NotDeclared { connector: id });
            }
            if supplied.insert(id.clone(), connector).is_some() {
                return Err(ConnectorError::DuplicateConnector { connector: id });
            }
        }

        for provider in &config.providers {
            if let Some(connector) = supplied.remove(provider) {
                registry.register(connector)?;
                continue;
            }

            let metadata =
                catalog::lookup(provider).ok_or_else(|| ConnectorError::UnknownConnector {
                    connector: provider.clone(),
                })?;

            let connector: Arc<dyn AuthConnector> = match metadata.status {
                ConnectorStatus::Supported if metadata.id == LocalConnector::ID => {
                    Arc::new(LocalConnector::new())
                }
                // A catalog entry marked supported with no implementation wired
                // up here must not silently degrade to something permissive.
                ConnectorStatus::Supported => Arc::new(DeclaredConnector::new(provider)),
                ConnectorStatus::Declared | ConnectorStatus::Unknown => {
                    Arc::new(DeclaredConnector::new(provider))
                }
            };
            registry.register(connector)?;
        }

        Ok(registry)
    }

    pub fn get(&self, id: &str) -> Result<Arc<dyn AuthConnector>, ConnectorError> {
        self.connectors
            .get(id)
            .cloned()
            .ok_or_else(|| ConnectorError::UnknownConnector {
                connector: id.to_string(),
            })
    }

    pub fn contains(&self, id: &str) -> bool {
        self.connectors.contains_key(id)
    }

    pub fn ids(&self) -> Vec<String> {
        self.connectors.keys().cloned().collect()
    }

    /// Deterministically ordered: the registry is keyed by connector id.
    pub fn metadata(&self) -> Vec<ConnectorMetadata> {
        self.connectors
            .values()
            .map(|connector| connector.metadata())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.connectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.connectors.is_empty()
    }
}

impl std::fmt::Debug for ConnectorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectorRegistry")
            .field("connectors", &self.ids())
            .finish()
    }
}
