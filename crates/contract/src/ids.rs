macro_rules! authority_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_string())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

authority_id!(TenantId);
authority_id!(PrincipalId);
authority_id!(AgentId);
authority_id!(AgentCredentialId);
authority_id!(IdentityId);
authority_id!(SessionId);
authority_id!(PolicyId);
authority_id!(StorageRootId);
authority_id!(ProviderName);
authority_id!(ProviderSubject);
authority_id!(Capability);
authority_id!(DelegationId);
authority_id!(AuditEventId);
authority_id!(RunId);
authority_id!(TaskId);
authority_id!(ExecutionCredentialId);
