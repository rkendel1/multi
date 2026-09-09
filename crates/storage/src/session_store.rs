use crate::StorageError;

pub trait SessionStore {
    fn create_session(
        &self,
        identity_id: &str,
        device_info: Option<String>,
    ) -> Result<Session, StorageError>;

    fn revoke_session(&self, session_id: &str) -> Result<(), StorageError>;

    fn list_sessions(&self, identity_id: &str) -> Result<Vec<Session>, StorageError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub identity_id: String,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}
