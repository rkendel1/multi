//! Connectors: the layer that proves external identity.
//!
//! ```text
//! Connector -> proves external identity -> ExternalIdentity
//!                                              |
//!                        resolved by the auth mesh (never by the connector)
//!                                              v
//!                                       AuthPort Principal
//! ```

pub mod catalog;
pub mod connector;
pub mod connectors;
pub mod registry;

pub use catalog::{describe, lookup};
pub use connector::{
    AuthChallenge, AuthConnector, AuthRequest, AuthResponse, ChallengeKind, ConnectorError,
    ConnectorKind, ConnectorMetadata, ConnectorStatus, ExternalIdentity,
};
pub use connectors::{DeclaredConnector, LocalAccount, LocalConnector};
pub use registry::ConnectorRegistry;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use appport_auth_mesh_dsl::parse_auth_block;

    use super::*;

    fn local_connector() -> LocalConnector {
        LocalConnector::new().with_account(
            LocalAccount::new("alice", "correct-horse").with_attribute("email", "alice@acme.test"),
        )
    }

    fn authenticate(
        connector: &dyn AuthConnector,
        tenant: &str,
        username: &str,
        password: &str,
    ) -> Result<ExternalIdentity, ConnectorError> {
        let request = AuthRequest::new(connector.id())
            .for_tenant(tenant)
            .with_parameter("username", username);
        let challenge = connector.begin(&request)?;
        let response = AuthResponse::to_challenge(&challenge)
            .for_tenant(tenant)
            .with_parameter("username", username)
            .with_parameter("password", password);
        connector.authenticate(&response)
    }

    #[test]
    fn local_connector_proves_external_identity() {
        let connector = local_connector();
        let identity =
            authenticate(&connector, "tenant-a", "alice", "correct-horse").expect("valid login");

        assert_eq!(identity.connector, "local");
        assert_eq!(identity.subject, "alice");
        assert_eq!(
            identity.attributes.get("email").map(String::as_str),
            Some("alice@acme.test")
        );
    }

    #[test]
    fn local_connector_fails_closed() {
        let connector = local_connector();

        assert_eq!(
            authenticate(&connector, "tenant-a", "alice", "wrong").unwrap_err(),
            ConnectorError::InvalidCredentials {
                connector: "local".to_string()
            }
        );
        assert_eq!(
            authenticate(&connector, "tenant-a", "mallory", "anything").unwrap_err(),
            ConnectorError::InvalidCredentials {
                connector: "local".to_string()
            }
        );

        // A challenge issued for one tenant cannot be replayed against another.
        let challenge = connector
            .begin(
                &AuthRequest::new("local")
                    .for_tenant("tenant-a")
                    .with_parameter("username", "alice"),
            )
            .unwrap();
        let replayed = AuthResponse::to_challenge(&challenge)
            .for_tenant("tenant-b")
            .with_parameter("username", "alice")
            .with_parameter("password", "correct-horse");
        assert_eq!(
            connector.authenticate(&replayed).unwrap_err(),
            ConnectorError::ChallengeMismatch {
                connector: "local".to_string()
            }
        );
    }

    #[test]
    fn declared_connectors_fail_explicitly() {
        for id in ["google", "github", "email"] {
            let connector = DeclaredConnector::new(id);
            assert_eq!(connector.metadata().status, ConnectorStatus::Declared);
            assert_eq!(
                connector.begin(&AuthRequest::new(id)).unwrap_err(),
                ConnectorError::Unsupported {
                    connector: id.to_string()
                }
            );
            assert_eq!(
                connector
                    .authenticate(&AuthResponse {
                        connector: id.to_string(),
                        ..AuthResponse::default()
                    })
                    .unwrap_err(),
                ConnectorError::Unsupported {
                    connector: id.to_string()
                }
            );
        }
    }

    #[test]
    fn registry_resolves_declared_providers() {
        let config = parse_auth_block(
            r#"
use auth {
  providers = [google, github, email, local]
}
"#,
        )
        .unwrap();

        let registry =
            ConnectorRegistry::from_config_with(&config, vec![Arc::new(local_connector())])
                .expect("registry builds from the declaration");

        assert_eq!(registry.ids(), vec!["email", "github", "google", "local"]);
        assert!(registry
            .get("local")
            .unwrap()
            .metadata()
            .status
            .is_supported());
        assert_eq!(
            registry.get("google").unwrap().metadata().status,
            ConnectorStatus::Declared
        );
        assert_eq!(
            registry.get("okta").map(|_| ()).unwrap_err(),
            ConnectorError::UnknownConnector {
                connector: "okta".to_string()
            }
        );

        let identity = authenticate(
            registry.get("local").unwrap().as_ref(),
            "tenant-a",
            "alice",
            "correct-horse",
        )
        .expect("registered connector authenticates");
        assert_eq!(identity.subject, "alice");
    }

    #[test]
    fn registry_rejects_unknown_and_undeclared_connectors() {
        let unknown = parse_auth_block("use auth { providers = [pigeon] }").unwrap();
        assert_eq!(
            ConnectorRegistry::from_config(&unknown).unwrap_err(),
            ConnectorError::UnknownConnector {
                connector: "pigeon".to_string()
            }
        );

        let config = parse_auth_block("use auth { providers = [google] }").unwrap();
        assert_eq!(
            ConnectorRegistry::from_config_with(&config, vec![Arc::new(local_connector())])
                .unwrap_err(),
            ConnectorError::NotDeclared {
                connector: "local".to_string()
            }
        );
    }

    #[test]
    fn registry_order_is_deterministic_regardless_of_declaration_order() {
        let a = parse_auth_block("use auth { providers = [github, local, google] }").unwrap();
        let b = parse_auth_block("use auth { providers = [google, github, local] }").unwrap();

        assert_eq!(
            ConnectorRegistry::from_config(&a).unwrap().ids(),
            ConnectorRegistry::from_config(&b).unwrap().ids()
        );
    }
}
