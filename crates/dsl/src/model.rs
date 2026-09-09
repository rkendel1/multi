#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    pub multi_tenant: bool,
    pub providers: Vec<String>,
    pub claims: Vec<ClaimDef>,
    pub isolation: IsolationMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimDef {
    pub name: String,
    pub kind: ClaimKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimKind {
    Enum(Vec<String>),
    String,
    Integer,
    Boolean,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationMode {
    Strict,
    SharedStorageWithPolicy,
}
