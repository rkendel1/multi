use appport_auth_mesh_contract::ClaimValue;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub id: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub capability: String,
    pub condition: Condition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    ClaimEquals { key: String, value: ClaimValue },
    ClaimIn { key: String, values: Vec<ClaimValue> },
    TimeBound { start: i64, end: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityEnvelope {
    pub granted_capabilities: Vec<String>,
}
