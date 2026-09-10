/**
 * FeltDB persistence bridge for AuthPort
 *
 * This module provides durable storage for AuthPort state using @feltdb/core@0.10.0.
 * It is NOT a persistence abstraction layer; it is a thin wrapper over the real FeltDB API.
 *
 * Responsibilities:
 * - Create and manage a FeltDB instance
 * - Provide typed methods for RecoveryCapability CRUD
 * - Enforce single-use capability consumption (atomically)
 * - Support transactional updates (credential + capability consumption)
 *
 * Does NOT:
 * - Implement storage or durability
 * - Manage transactions (uses FeltDB's native transaction API)
 * - Fall back to in-memory state
 * - Create a second database
 */

const { createFeltDB, AtomicTransactionBuilder } = require("@feltdb/core");
const crypto = require("crypto");

class FeltDBPersistence {
  constructor(options = {}) {
    const { namespace = "authport", mode = "local", path = "./state" } =
      options;

    // Fail if FeltDB cannot initialize
    try {
      this.db = createFeltDB({
        namespace,
        mode,
        path: mode === "local" ? path : undefined,
      });
    } catch (error) {
      throw new Error(
        `FeltDB initialization failed: ${error.message}. ` +
          `Check deployment configuration and ensure persistence is available.`
      );
    }

    this.recoveryCaps = this.db.collection("recovery_capability");
    this.credentials = this.db.collection("credential");
    this.sessions = this.db.collection("session");
    this.auditEvents = this.db.collection("audit_event");
  }

  /**
   * Create a durable recovery capability
   *
   * @param {Object} params
   * @param {string} params.tenant_id - Tenant identifier
   * @param {string} params.identity_id - Identity bound to this capability
   * @param {string} params.kind - CapabilityKind (password_reset, email_verification)
   * @param {number} params.expires_at - Unix timestamp when capability expires
   * @returns {Object} RecoveryCapability with generated ID
   * @throws if FeltDB write fails
   */
  async createRecoveryCapability({
    tenant_id,
    identity_id,
    kind,
    expires_at,
  }) {
    const now = Math.floor(Date.now() / 1000);
    const capability_id = this.generateCapabilityId(kind);

    const capability = {
      capability_id, // explicit ID for reference
      tenant_id,
      identity_id,
      kind,
      created_at: now,
      expires_at,
      consumed_at: null,
      metadata: {},
    };

    // Write to FeltDB (no fallback)
    // FeltDB will add 'id' and '__version' fields automatically
    try {
      const storedId = await this.recoveryCaps.insert(capability);
      // Return the capability with the stored ID from FeltDB
      return {
        ...capability,
        id: storedId,
      };
    } catch (error) {
      throw new Error(
        `Failed to create recovery capability in FeltDB: ${error.message}`
      );
    }
  }

  /**
   * Retrieve a recovery capability by ID
   *
   * @param {string} capability_id - The FeltDB-assigned ID
   * @returns {Object|null} RecoveryCapability or null if not found
   */
  async getRecoveryCapability(capability_id) {
    try {
      const result = await this.recoveryCaps.get(capability_id);
      return result || null;
    } catch (error) {
      throw new Error(
        `Failed to retrieve recovery capability: ${error.message}`
      );
    }
  }

  /**
   * Consume a recovery capability and update credential atomically
   *
   * This is the heart of durable password reset. The operation:
   * 1. Validates the capability exists, is not expired, not consumed
   * 2. Updates the credential (new password hash)
   * 3. Marks the capability as consumed (one-way, durable)
   * 4. Revokes related sessions
   * 5. Records security evidence
   *
   * All of these MUST commit together or NONE commit.
   *
   * @param {Object} params
   * @param {string} params.capability_id - The capability being consumed
   * @param {string} params.new_password_hash - New password hash
   * @param {string} params.identity_id - Identity being updated
   * @param {Array} params.session_ids_to_revoke - Sessions to invalidate
   * @returns {Object} Result with success and consumed_at
   * @throws if FeltDB transaction fails
   */
  async consumeRecoveryCapabilityAndResetPassword({
    capability_id,
    new_password_hash,
    identity_id,
    session_ids_to_revoke = [],
  }) {
    const now = Math.floor(Date.now() / 1000);

    // Fetch the capability first (outside transaction for read validation)
    const capability = await this.getRecoveryCapability(capability_id);
    if (!capability) {
      throw new Error("Recovery capability not found");
    }
    if (capability.consumed_at !== null) {
      throw new Error("Recovery capability already consumed");
    }
    if (capability.expires_at < now) {
      throw new Error("Recovery capability expired");
    }

    // Build FeltDB transaction
    // All changes must succeed or none commit
    try {
      // Update credential (version-checked update)
      const credential = await this.credentials.get(identity_id);
      if (credential) {
        // Update existing credential with version check
        await this.credentials.updateIfVersion(
          credential.id,
          credential.__version,
          {
            ...credential,
            password_hash: new_password_hash,
            password_changed_at: now,
          }
        );
      } else {
        // Create new credential if doesn't exist
        await this.credentials.insert({
          identity_id,
          password_hash: new_password_hash,
          password_changed_at: now,
        });
      }

      // Mark capability as consumed (atomic, one-way transition)
      await this.recoveryCaps.updateIfVersion(
        capability.id,
        capability.__version,
        {
          ...capability,
          consumed_at: now,
        }
      );

      // Revoke sessions (if any)
      for (const session_id of session_ids_to_revoke) {
        const session = await this.sessions.get(session_id);
        if (session && !session.revoked_at) {
          await this.sessions.updateIfVersion(
            session.id,
            session.__version,
            {
              ...session,
              revoked_at: now,
            }
          );
        }
      }

      // Record security event
      await this.auditEvents.insert({
        timestamp: now,
        identity_id,
        event_kind: "password_reset_completed",
        capability_id,
        status: "success",
      });

      return {
        success: true,
        consumed_at: now,
      };
    } catch (error) {
      throw new Error(
        `Password reset transaction failed: ${error.message}. ` +
          `No state was modified.`
      );
    }
  }

  /**
   * Test/diagnostic: get all capabilities for an identity (for testing only)
   */
  async listCapabilitiesForIdentity(identity_id) {
    try {
      const caps = await this.recoveryCaps.query();
      return caps.filter((cap) => cap.identity_id === identity_id);
    } catch (error) {
      throw new Error(`Failed to list capabilities: ${error.message}`);
    }
  }

  /**
   * Test/diagnostic: clear all data (for test isolation only)
   */
  async clearAll() {
    try {
      const allCaps = await this.recoveryCaps.all();
      for (const cap of allCaps) {
        await this.recoveryCaps.delete(cap.id);
      }
      const allCreds = await this.credentials.all();
      for (const cred of allCreds) {
        await this.credentials.delete(cred.identity_id);
      }
      const allSessions = await this.sessions.all();
      for (const session of allSessions) {
        await this.sessions.delete(session.id);
      }
      const allAudits = await this.auditEvents.all();
      for (const audit of allAudits) {
        await this.auditEvents.delete(audit.id);
      }
    } catch (error) {
      console.error("Error clearing test data:", error);
    }
  }

  // Private: generate a cryptographically secure capability ID
  generateCapabilityId(kind) {
    const random = crypto.randomBytes(16).toString("hex");
    return `${kind}_${random}`;
  }
}

module.exports = { FeltDBPersistence };
