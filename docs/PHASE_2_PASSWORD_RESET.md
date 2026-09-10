# Phase 2: FeltDB-Backed Password Reset (First Durable Workflow)

## Current Problem

Password reset tokens are stored in `ChallengeStore` using an in-memory HashMap:
```rust
// crates/boundary/src/ceremony.rs
pub(crate) struct ChallengeStore {
    entries: Mutex<HashMap<[u8; 32], Challenge>>,
}
```

**If the server restarts between password reset request and consumption, the token is lost.** The reset link becomes invalid, creating a broken UX.

## Workflow

### Current (in-memory, broken on restart):
```
1. POST /auth/password/forgot
   ↓
2. Create token in ChallengeStore (HashMap in memory)
   ↓
3. Call MailPort → send email with token
   ↓
4. [SERVER RESTART]
   ↓
5. User clicks reset link
   ↓
6. POST /auth/password/reset?token=...
   ↓
7. Look up token in ChallengeStore
   ↓
8. ❌ Token not found (lost during restart!)
```

### Target (FeltDB-backed, durable):
```
1. POST /auth/password/forgot
   ↓
2. Create durable RecoveryCapability in FeltDB
   ├── capability_id (opaque)
   ├── identity_id (bound to who can use it)
   ├── created_at
   ├── expires_at
   ├── status (pending → consumed/revoked)
   └── intent (password_reset)
   ↓
3. Call MailPort → send email with capability_id
   ↓
4. [SERVER RESTART]
   ↓
5. User clicks reset link
   ↓
6. POST /auth/password/reset with capability_id
   ↓
7. FeltDB transaction:
   ├── Validate capability (exists, not expired, not consumed)
   ├── Update credential (new password hash)
   ├── Mark capability as consumed
   ├── Revoke all other sessions
   ├── Record security event
   ├── COMMIT (all or nothing)
   ↓
8. ✅ Capability still valid after restart, password reset succeeds
```

## State Model: RecoveryCapability

Persists in FeltDB:

```rust
// In contract or storage
pub struct RecoveryCapability {
    pub id: CapabilityId,        // opaque, URL-safe
    pub tenant_id: TenantId,      // for multi-tenancy
    pub identity_id: IdentityId,  // who can use this
    pub intent: CapabilityIntent, // password_reset, email_verification, etc.
    pub created_at: i64,          // unix seconds
    pub expires_at: i64,          // unix seconds
    pub consumed_at: Option<i64>, // if used
    pub metadata: Map<String>,    // intent-specific data
}

pub enum CapabilityIntent {
    PasswordReset,
    EmailVerification,
}
```

## Key Properties

**Immutable once created:**
- identity binding (cannot be transferred)
- intent (cannot change reset → verification)
- created_at and expires_at

**Mutable only to consumed:**
- status: pending → consumed (one-way transition)

**Never:**
- Updated mid-operation (atomic consume or rollback)
- Cascaded to multiple identities
- Checked outside transaction boundary

## FeltDB Transaction Requirements

When consuming a recovery capability:

```
BEGIN TRANSACTION

1. Validate capability
   - Read RecoveryCapability
   - Assert: not consumed, not expired, matches identity
   
2. Update credential
   - Read current Credential
   - Hash new password
   - Write new Credential with updated hash, timestamp
   
3. Consume capability
   - Update RecoveryCapability.consumed_at = now()
   
4. Revoke sessions
   - For SessionId in identity.sessions:
     - Update Session.revoked_at = now()
   
5. Record security event
   - Write AuditEvent:
     kind: password_reset_completed
     identity_id: ...
     capability_id: ...
     timestamp: now()

COMMIT

-- If any step fails, ROLLBACK. None of the above happen.
```

**Critical:** Either ALL steps succeed or NONE. No partial updates.

FeltDB 0.10.0 provides transaction primitives. We consume them via @feltdb/core.

## Integration Points

### 1. Boundary Runtime
Current:
```rust
pub fn forgot_password(&self, request: &BoundaryRequest) -> Result<(), AuthError> {
    let token = self.challenges.issue(...)?;  // in-memory
    self.mail.send(..., &token)?;
}

pub fn reset_password(&self, request: &BoundaryRequest) -> Result<(), AuthError> {
    let challenge = self.challenges.consume(&token)?;  // in-memory lookup
    self.credentials.update(...)?;
}
```

Target:
```rust
pub fn forgot_password(&self, request: &BoundaryRequest) -> Result<(), AuthError> {
    let capability = self.state_repo.create_recovery_capability(...)?;  // FeltDB
    self.mail.send(..., &capability.id)?;
}

pub fn reset_password(&self, request: &BoundaryRequest) -> Result<(), AuthError> {
    // FeltDB transaction
    self.state_repo.consume_recovery_capability_and_reset_password(...)?;
}
```

### 2. AuthStateRepository
Adds methods:
```rust
pub fn create_recovery_capability(
    &self,
    identity_id: &IdentityId,
    intent: CapabilityIntent,
    ttl_seconds: i64,
) -> Result<RecoveryCapability, FeltDBError>

pub fn consume_recovery_capability_and_reset_password(
    &self,
    capability_id: &CapabilityId,
    new_password_hash: &str,
) -> Result<(), FeltDBError>
```

Both delegate to @feltdb/core, never reimplement transaction logic.

### 3. Storage Layer
Add:
```rust
pub trait RecoveryCapabilityStore {
    fn create_capability(...) -> Result<RecoveryCapability, StorageError>;
    fn get_capability(...) -> Result<Option<RecoveryCapability>, StorageError>;
    fn consume_capability(...) -> Result<(), StorageError>;
}
```

MemoryStores continues for tests, but tests should exercise restart persistence.

### 4. FeltDB Schema (Conceptual)

When FeltDB is initialized with AuthPort config, it creates:
```
collections:
  /identity          # canonical users
  /credential        # password hashes, current
  /external_identity # provider linkage
  /session           # active sessions
  /recovery_capability  # password_reset, email_verify
  /verification_token   # email verification
  /audit             # append-only security events
  /tenant_membership # multi-tenancy
```

## Acceptance Criteria for Phase 2

- ☐ RecoveryCapability model added to contract
- ☐ RecoveryCapabilityStore trait in storage boundary
- ☐ AuthStateRepository has create/consume methods
- ☐ forgot_password() creates durable capability
- ☐ reset_password() consumes capability in FeltDB transaction
- ☐ Restart test: request reset, restart, consume → succeeds
- ☐ Expiry test: create expired capability, consume → rejected
- ☐ Reuse test: consume capability, try again → rejected
- ☐ Atomicity test: failure during credential update → rollback, capability still valid
- ☐ Cross-session test: reset password, other sessions revoked durably
- ☐ MailPort integration: recovery capability flows to email, not vice versa
- ☐ Security evidence: reset attempt, reset completion recorded in audit

## Implementation Order

1. Add RecoveryCapability to contract
2. Add RecoveryCapabilityStore trait
3. Create FFI/RPC binding to @feltdb/core (provisional)
4. Implement FeltDB-backed RecoveryCapabilityStore
5. Update AuthStateRepository to use it
6. Update boundary runtime forgot/reset methods
7. Add test suite with restart scenarios
8. Remove ChallengeStore (or keep for compatibility, mark deprecated)

## What This Proves

Once password reset is durable:
- FeltDB integration is end-to-end validated
- Transaction semantics work
- Restart persistence works
- No in-memory fallback was necessary
- MailPort boundary is preserved
- Security evidence is durable

This is the template for migrating remaining state (identity, credential, session, etc.) in Phase 3+.
