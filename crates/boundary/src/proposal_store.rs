use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::control::{AuthorityChange, LiveAuthorityState, Preview};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalStatus {
    Pending,
    Applied,
    Rejected,
}

impl ProposalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoredProposal {
    pub id: String,
    pub change: AuthorityChange,
    pub preview: Preview,
    pub revision: u64,
    pub status: ProposalStatus,
    pub created_at: SystemTime,
    pub applied_at: Option<SystemTime>,
    pub change_id: Option<String>,
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProposalMetadata {
    pub id: String,
    pub change_type: String,
    pub status: ProposalStatus,
    pub created_at: SystemTime,
    pub applied_at: Option<SystemTime>,
}

#[derive(Debug, Clone)]
pub struct ChangeRecord {
    pub change_id: String,
    pub proposal_id: String,
    pub change: AuthorityChange,
    pub previous_state: LiveAuthorityState,
    pub resulting_state: LiveAuthorityState,
    pub applied_at: SystemTime,
    pub applied_by: Option<String>,
    pub reverted_change_id: Option<String>,
}

pub trait ProposalStore: Send + Sync {
    fn allocate_proposal_id(&self) -> String;
    fn store_proposal(&self, proposal: StoredProposal) -> Result<(), String>;
    fn retrieve_proposal(&self, proposal_id: &str) -> Result<StoredProposal, String>;
    fn list_proposals(&self, limit: usize, offset: usize) -> Result<Vec<ProposalMetadata>, String>;
    fn mark_applied(
        &self,
        proposal_id: &str,
        change_id: String,
        new_revision: u64,
    ) -> Result<(), String>;
    fn mark_rejected(&self, proposal_id: &str, reason: String) -> Result<(), String>;
    fn store_change_record(&self, record: ChangeRecord) -> Result<(), String>;
    fn retrieve_change_record(&self, change_id: &str) -> Result<ChangeRecord, String>;
    fn list_change_records(&self, limit: usize, offset: usize) -> Result<Vec<ChangeRecord>, String>;
}

#[derive(Debug, Clone)]
pub struct MemoryProposalStore {
    proposals: Arc<Mutex<BTreeMap<String, StoredProposal>>>,
    changes: Arc<Mutex<BTreeMap<String, ChangeRecord>>>,
    next_id: Arc<Mutex<u64>>,
}

impl MemoryProposalStore {
    pub fn new() -> Self {
        Self {
            proposals: Arc::new(Mutex::new(BTreeMap::new())),
            changes: Arc::new(Mutex::new(BTreeMap::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
    }
}

impl Default for MemoryProposalStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ProposalStore for MemoryProposalStore {
    fn allocate_proposal_id(&self) -> String {
        let mut next = self.next_id.lock().unwrap();
        let id = format!("proposal-{}", *next);
        *next += 1;
        id
    }

    fn store_proposal(&self, proposal: StoredProposal) -> Result<(), String> {
        let mut proposals = self.proposals.lock().unwrap();
        if proposals.contains_key(&proposal.id) {
            return Err(format!("proposal `{}` already exists", proposal.id));
        }
        proposals.insert(proposal.id.clone(), proposal);
        Ok(())
    }

    fn retrieve_proposal(&self, proposal_id: &str) -> Result<StoredProposal, String> {
        self.proposals
            .lock()
            .unwrap()
            .get(proposal_id)
            .cloned()
            .ok_or_else(|| format!("proposal `{}` was not found", proposal_id))
    }

    fn list_proposals(&self, limit: usize, offset: usize) -> Result<Vec<ProposalMetadata>, String> {
        let mut proposals = self
            .proposals
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        proposals.sort_by_key(|proposal| proposal.created_at);
        proposals.reverse();
        Ok(proposals
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|proposal| ProposalMetadata {
                id: proposal.id,
                change_type: proposal.change.change_type().to_string(),
                status: proposal.status,
                created_at: proposal.created_at,
                applied_at: proposal.applied_at,
            })
            .collect())
    }

    fn mark_applied(
        &self,
        proposal_id: &str,
        change_id: String,
        _new_revision: u64,
    ) -> Result<(), String> {
        let mut proposals = self.proposals.lock().unwrap();
        let proposal = proposals
            .get_mut(proposal_id)
            .ok_or_else(|| format!("proposal `{}` was not found", proposal_id))?;
        proposal.status = ProposalStatus::Applied;
        proposal.applied_at = Some(SystemTime::now());
        proposal.change_id = Some(change_id);
        Ok(())
    }

    fn mark_rejected(&self, proposal_id: &str, reason: String) -> Result<(), String> {
        let mut proposals = self.proposals.lock().unwrap();
        let proposal = proposals
            .get_mut(proposal_id)
            .ok_or_else(|| format!("proposal `{}` was not found", proposal_id))?;
        proposal.status = ProposalStatus::Rejected;
        proposal.rejection_reason = Some(reason);
        Ok(())
    }

    fn store_change_record(&self, record: ChangeRecord) -> Result<(), String> {
        self.changes
            .lock()
            .unwrap()
            .insert(record.change_id.clone(), record);
        Ok(())
    }

    fn retrieve_change_record(&self, change_id: &str) -> Result<ChangeRecord, String> {
        self.changes
            .lock()
            .unwrap()
            .get(change_id)
            .cloned()
            .ok_or_else(|| format!("change `{}` was not found", change_id))
    }

    fn list_change_records(&self, limit: usize, offset: usize) -> Result<Vec<ChangeRecord>, String> {
        let mut records = self
            .changes
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by_key(|record| record.applied_at);
        records.reverse();
        Ok(records.into_iter().skip(offset).take(limit).collect())
    }
}
