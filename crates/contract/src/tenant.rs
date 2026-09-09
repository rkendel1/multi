#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    pub id: String,
    pub namespace: String,
    pub policy_id: String,
    pub storage_root_id: String,
}
