#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractVersion {
    pub major: u32,
    pub minor: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineSemantics {
    pub max_age_seconds: u64,
    pub must_revalidate: bool,
}
