use std::collections::HashMap;

use crate::{
    ClaimValue, ContractVersion, IdentityId, OfflineSemantics, ProviderName, ProviderSubject,
    TenantId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub id: IdentityId,
    pub provider: ProviderName,
    pub provider_subject: ProviderSubject,
    pub tenant_id: TenantId,
    pub claims: Claims,
    pub version: ContractVersion,
    pub offline: OfflineSemantics,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub values: HashMap<String, ClaimValue>,
}
