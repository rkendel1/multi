#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimValue {
    Enum(String),
    String(String),
    Integer(i64),
    Boolean(bool),
}
