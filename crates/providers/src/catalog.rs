use crate::connector::{ConnectorKind, ConnectorMetadata, ConnectorStatus};

/// The single source of truth for connector identity and support level.
///
/// The registry, the generated auth surface and the default UI all read this
/// catalog; there is no second hand-maintained provider list anywhere.
pub const CATALOG: &[(&str, &str, ConnectorKind, ConnectorStatus)] = &[
    (
        "local",
        "Local Directory",
        ConnectorKind::Local,
        ConnectorStatus::Supported,
    ),
    (
        "password",
        "Password",
        ConnectorKind::Password,
        ConnectorStatus::Declared,
    ),
    (
        "google",
        "Google",
        ConnectorKind::Oauth,
        ConnectorStatus::Declared,
    ),
    (
        "github",
        "GitHub",
        ConnectorKind::Oauth,
        ConnectorStatus::Declared,
    ),
    (
        "microsoft",
        "Microsoft",
        ConnectorKind::Oauth,
        ConnectorStatus::Declared,
    ),
    (
        "apple",
        "Apple",
        ConnectorKind::Oauth,
        ConnectorStatus::Declared,
    ),
    (
        "email",
        "Email",
        ConnectorKind::Email,
        ConnectorStatus::Declared,
    ),
    (
        "magic_link",
        "Magic Link",
        ConnectorKind::MagicLink,
        ConnectorStatus::Declared,
    ),
    (
        "sso",
        "Enterprise SSO",
        ConnectorKind::EnterpriseSso,
        ConnectorStatus::Declared,
    ),
    (
        "jwt",
        "JWT",
        ConnectorKind::Token,
        ConnectorStatus::Declared,
    ),
];

pub fn lookup(id: &str) -> Option<ConnectorMetadata> {
    CATALOG
        .iter()
        .find(|(catalog_id, _, _, _)| *catalog_id == id)
        .map(|(id, display_name, kind, status)| ConnectorMetadata {
            id: (*id).to_string(),
            display_name: (*display_name).to_string(),
            kind: *kind,
            status: *status,
        })
}

/// Metadata for a declared connector, including ones the catalog does not know.
/// An unrecognised connector is reported as `Unknown` rather than guessed at,
/// and every path that could authenticate through it fails closed.
pub fn describe(id: &str) -> ConnectorMetadata {
    lookup(id).unwrap_or_else(|| ConnectorMetadata {
        id: id.to_string(),
        display_name: id.to_string(),
        kind: ConnectorKind::Token,
        status: ConnectorStatus::Unknown,
    })
}

pub fn all() -> Vec<ConnectorMetadata> {
    CATALOG.iter().map(|(id, _, _, _)| describe(id)).collect()
}
