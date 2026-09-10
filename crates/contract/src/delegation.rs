use std::collections::BTreeMap;

use crate::{Capability, ClaimValue, DelegationId, PrincipalId, TenantId};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourceScope {
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub attributes: BTreeMap<String, ClaimValue>,
}

impl ResourceScope {
    pub fn any() -> Self {
        Self::default()
    }

    pub fn resource(resource_type: impl Into<String>) -> Self {
        Self {
            resource_type: Some(resource_type.into()),
            resource_id: None,
            attributes: BTreeMap::new(),
        }
    }

    pub fn exact(resource_type: impl Into<String>, resource_id: impl Into<String>) -> Self {
        Self {
            resource_type: Some(resource_type.into()),
            resource_id: Some(resource_id.into()),
            attributes: BTreeMap::new(),
        }
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: ClaimValue) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }

    pub fn is_unconstrained(&self) -> bool {
        self.resource_type.is_none() && self.resource_id.is_none() && self.attributes.is_empty()
    }

    pub fn is_subset_of(&self, parent: &ResourceScope) -> bool {
        if let Some(parent_type) = &parent.resource_type {
            if self.resource_type.as_ref() != Some(parent_type) {
                return false;
            }
        }
        if let Some(parent_id) = &parent.resource_id {
            if self.resource_id.as_ref() != Some(parent_id) {
                return false;
            }
        }
        parent
            .attributes
            .iter()
            .all(|(key, value)| self.attributes.get(key) == Some(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationStatus {
    Active,
    Pending,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub id: DelegationId,
    pub delegator: PrincipalId,
    pub delegate: PrincipalId,
    pub tenant_id: TenantId,
    pub capabilities: Vec<Capability>,
    pub resource_scope: ResourceScope,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub chain: Vec<DelegationId>,
}

impl Delegation {
    pub fn is_valid_at(&self, now: i64) -> bool {
        self.status_at(now) == DelegationStatus::Active
    }

    pub fn status_at(&self, now: i64) -> DelegationStatus {
        if self.revoked_at.is_some() {
            DelegationStatus::Revoked
        } else if self.issued_at > now {
            DelegationStatus::Pending
        } else if self
            .expires_at
            .map(|expires_at| now >= expires_at)
            .unwrap_or(false)
        {
            DelegationStatus::Expired
        } else {
            DelegationStatus::Active
        }
    }
}
