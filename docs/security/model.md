# Security model

The client never defines the principal, tenant, claims or capabilities used for
authorization. AuthBoundry reconstructs them from verified server-owned state.

The boundary denies missing or invalid credentials; expired or revoked
sessions; unknown or wrong tenants; revoked agents; expired or revoked
delegations; ungranted capabilities; missing policies or claims; unsupported
connectors; unknown route policies; and unauditable decisions. Client-side
`can()` is a rendering hint, not a security decision.
