use std::collections::HashMap;

use crate::{ClaimValue, ContractVersion, OfflineSemantics};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub id: String,
    pub provider: String,
    pub tenant_id: String,
    pub claims: Claims,
    pub version: ContractVersion,
    pub offline: OfflineSemantics,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub values: HashMap<String, ClaimValue>,
}
