use std::collections::HashMap;
use std::sync::Mutex;

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyKind {
    PasswordReset,
    EmailVerification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailMessage {
    pub template: String,
    pub identity: String,
    pub to: String,
    pub tenant: String,
    pub variables: HashMap<String, String>,
    pub idempotency_key: String,
}

pub trait MailPort: Send + Sync {
    fn send(&self, message: MailMessage) -> Result<(), String>;
}

#[derive(Default)]
pub struct MemoryMailPort {
    messages: Mutex<Vec<MailMessage>>,
}

impl MemoryMailPort {
    pub fn messages(&self) -> Vec<MailMessage> {
        self.messages
            .lock()
            .map(|items| items.clone())
            .unwrap_or_default()
    }
}

impl MailPort for MemoryMailPort {
    fn send(&self, message: MailMessage) -> Result<(), String> {
        self.messages
            .lock()
            .map_err(|_| "mail inbox unavailable".to_string())?
            .push(message);
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct Challenge {
    kind: CeremonyKind,
    tenant: String,
    account: String,
    expires_at: i64,
    consumed: bool,
    revoked: bool,
}

#[derive(Default)]
pub(crate) struct ChallengeStore {
    entries: Mutex<HashMap<[u8; 32], Challenge>>,
}

impl ChallengeStore {
    pub(crate) fn issue(
        &self,
        kind: CeremonyKind,
        tenant: &str,
        account: &str,
        expires_at: i64,
    ) -> Result<String, String> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let token = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        self.entries
            .lock()
            .map_err(|_| "challenge store unavailable".to_string())?
            .insert(
                hash(&token),
                Challenge {
                    kind,
                    tenant: tenant.to_string(),
                    account: account.to_string(),
                    expires_at,
                    consumed: false,
                    revoked: false,
                },
            );
        Ok(token)
    }

    pub(crate) fn consume(
        &self,
        token: &str,
        kind: CeremonyKind,
        now: i64,
    ) -> Result<(String, String), String> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| "challenge store unavailable".to_string())?;
        let entry = entries
            .get_mut(&hash(token))
            .ok_or_else(|| "invalid recovery challenge".to_string())?;
        if entry.kind != kind || entry.revoked || entry.consumed || now >= entry.expires_at {
            return Err("invalid or expired recovery challenge".to_string());
        }
        entry.consumed = true;
        Ok((entry.tenant.clone(), entry.account.clone()))
    }

    pub(crate) fn revoke(&self, token: &str) -> bool {
        self.entries
            .lock()
            .ok()
            .and_then(|mut entries| {
                entries
                    .get_mut(&hash(token))
                    .map(|entry| entry.revoked = true)
            })
            .is_some()
    }
}

fn hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}
