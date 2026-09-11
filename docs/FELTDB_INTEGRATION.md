# FeltDB 0.10.0 Integration

## Overview

AuthBoundry now uses FeltDB 0.10.0 as its default and only authoritative state substrate for production.

**Exact dependency:**
```json
{
  "@feltdb/core": "0.10.0"
}
```

No caret ranges. No tildes. Exactly 0.10.0.

## Architecture

```
AuthBoundry (authentication & authorization semantics)
    ↓
AuthStateRepository (narrow semantic boundary)
    ↓
@feltdb/core 0.10.0 (durable state and infrastructure)
    ↓
FeltDB deployment resolution
    ├── local durable
    ├── remote/self-hosted
    ├── managed
    └── browser durable
```

## Key Principles

### 1. AuthBoundry owns authentication semantics
- Identity (canonical application identity)
- Credentials (password hashes, credential status)
- Sessions (durable session lifecycle)
- Recovery capabilities (password reset)
- Verification (email verification)
- External identities (provider linking)
- Tenants and memberships
- Claims and authorization state
- Agent principals
- Security evidence (audit trail)

### 2. FeltDB owns persistence infrastructure
- Storage engine and durability guarantees
- Transaction semantics
- Event log and ordering
- Deployment resolution (local, remote, managed, browser)
- Connection management
- Version control and schema evolution

### 3. AuthBoundry must NOT implement
- ~~AuthDatabase~~
- ~~AuthStore~~
- ~~AuthPersistenceEngine~~
- ~~AuthCollection~~
- ~~AuthTransaction~~
- ~~AuthEventStore~~
- ~~AuthOutbox~~
- ~~AuthDeploymentResolver~~
- ~~FeltDB-like storage~~
- ~~In-memory fallback~~

### 4. Failure mode is fail-closed
If FeltDB cannot initialize with the configured deployment:
- AuthBoundry startup fails
- Error message names the deployment mode and missing configuration
- There is NO fallback to in-memory state
- No production authentication state depends on process memory

## Current State (Phase 1)

✅ Dependency pinned exactly  
✅ CI verification in place  
✅ AuthStateRepository boundary created  
⏳ FeltDB client integration (via FFI or JS binding)  
⏳ State migration to FeltDB  
⏳ Transaction semantics  
⏳ Password reset workflow  
⏳ Deployment proof testing  

## Next: Phase 2

Move the following into FeltDB:
- Identities
- Credentials
- External identities
- Sessions
- Recovery capabilities
- Email verification capabilities
- Tenants and memberships
- Claims
- Agent principals
- Security evidence/audit

## Next: Phase 3

Implement password reset as the first end-to-end durable workflow:
```
1. Request reset
2. Create durable recovery capability in FeltDB
3. Call MailPort
4. User clicks link
5. FeltDB transaction:
   - Validate capability
   - Update credential
   - Consume capability
   - Revoke sessions
   - Record security event
   - COMMIT
```

Restart between any step → capability still valid, state preserved.

## Testing

### Unit Tests
Test AuthStateRepository behavior and FeltDB configuration validation.

### Integration Tests
Use real @feltdb/core (never mock).

### End-to-End Tests
1. Restart durability: create state, restart runtime, verify state recovered
2. Failure scenarios: FeltDB unavailable → startup fails
3. Transaction atomicity: password reset must commit or roll back entirely

## Related

- `crates/feltdb-adapter/` — AuthStateRepository and FeltDB integration boundary
- `test/verify-feltdb-version.js` — CI verification that FeltDB is pinned correctly
- `storage_boundary.rs` — Storage topology that defaults to FeltDB
