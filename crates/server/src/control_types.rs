use crate::http::JsonValue;
use std::time::SystemTime;

/// Description of a running AuthBoundry application
#[derive(Debug, Clone)]
pub struct ApplicationDescription {
    pub name: String,
    pub deployment_mode: String, // "embedded" or "standalone"
    pub contract_fingerprint: String,
    pub surface_fingerprint: String,
    pub started_at: SystemTime,
    pub uptime_seconds: u64,
}

impl ApplicationDescription {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::Object(vec![
            ("name".to_string(), JsonValue::String(self.name.clone())),
            (
                "deployment_mode".to_string(),
                JsonValue::String(self.deployment_mode.clone()),
            ),
            (
                "contract_fingerprint".to_string(),
                JsonValue::String(self.contract_fingerprint.clone()),
            ),
            (
                "surface_fingerprint".to_string(),
                JsonValue::String(self.surface_fingerprint.clone()),
            ),
            (
                "started_at".to_string(),
                JsonValue::Number(
                    self.started_at
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as f64,
                ),
            ),
            (
                "uptime_seconds".to_string(),
                JsonValue::Number(self.uptime_seconds as f64),
            ),
        ])
    }
}

/// Protection level for a route
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteProtection {
    None,
    SessionRequired,
    CapabilityRequired(String),
}

impl RouteProtection {
    pub fn to_json(&self) -> JsonValue {
        match self {
            Self::None => JsonValue::String("none".to_string()),
            Self::SessionRequired => JsonValue::String("session_required".to_string()),
            Self::CapabilityRequired(cap) => JsonValue::Object(vec![
                (
                    "type".to_string(),
                    JsonValue::String("capability_required".to_string()),
                ),
                ("capability".to_string(), JsonValue::String(cap.clone())),
            ]),
        }
    }
}

/// Description of an AuthBoundry route
#[derive(Debug, Clone)]
pub struct RouteDescription {
    pub path: String,
    pub methods: Vec<String>,
    pub protection: RouteProtection,
    pub aliases: Vec<String>,
}

impl RouteDescription {
    pub fn to_json(&self) -> JsonValue {
        JsonValue::Object(vec![
            ("path".to_string(), JsonValue::String(self.path.clone())),
            (
                "methods".to_string(),
                JsonValue::Array(
                    self.methods
                        .iter()
                        .map(|m| JsonValue::String(m.clone()))
                        .collect(),
                ),
            ),
            ("protection".to_string(), self.protection.to_json()),
            (
                "aliases".to_string(),
                JsonValue::Array(
                    self.aliases
                        .iter()
                        .map(|a| JsonValue::String(a.clone()))
                        .collect(),
                ),
            ),
        ])
    }
}
