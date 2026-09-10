import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { MailPortError, ERROR_CODES } from "@mailerport/core";

const sleepBuffer = new Int32Array(new SharedArrayBuffer(4));
const clone = (value) => structuredClone(value);
const iso = (time = Date.now()) => new Date(time).toISOString();
const event = (type, message, details = {}) => ({ event_id: `evt_${randomUUID().replaceAll("-", "")}`,
  message_id: message.message_id, timestamp: iso(), event_type: type, attempt: message.attempt || 0,
  worker_id: message.claimed_by || null, ...details });

export class FileMailStore {
  constructor({ filePath } = {}) {
    this.filePath = filePath;
    this.lockPath = filePath ? `${filePath}.lock` : null;
    this.memory = new Map();
    this.#reload();
  }
  #reload() {
    if (!this.filePath) return;
    this.memory.clear();
    if (!fs.existsSync(this.filePath)) return;
    const raw = fs.readFileSync(this.filePath, "utf8");
    for (const item of raw.trim() ? JSON.parse(raw) : []) this.memory.set(item.message_id, item);
  }
  #commit() {
    if (!this.filePath) return;
    const directoryPath = path.dirname(path.resolve(this.filePath));
    fs.mkdirSync(directoryPath, { recursive: true });
    const temporary = `${this.filePath}.${process.pid}.${randomUUID()}.tmp`;
    const fd = fs.openSync(temporary, "wx", 0o600);
    try { fs.writeFileSync(fd, JSON.stringify([...this.memory.values()], null, 2)); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
    fs.renameSync(temporary, this.filePath);
    const directory = fs.openSync(directoryPath, "r");
    try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  }
  #locked(callback) {
    if (!this.lockPath) return callback();
    fs.mkdirSync(path.dirname(path.resolve(this.lockPath)), { recursive: true });
    let fd;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try { fd = fs.openSync(this.lockPath, "wx", 0o600); fs.writeFileSync(fd, String(process.pid)); break; }
      catch (error) {
        if (error.code !== "EEXIST" || attempt === 99) throw error;
        try {
          const owner = Number(fs.readFileSync(this.lockPath, "utf8"));
          if (owner) process.kill(owner, 0);
        } catch (ownerError) {
          if (ownerError.code === "ESRCH" || ownerError.code === "ENOENT") {
            try { fs.unlinkSync(this.lockPath); } catch {}
            continue;
          }
        }
        Atomics.wait(sleepBuffer, 0, 0, 5);
      }
    }
    try { this.#reload(); return callback(); }
    finally { if (fd !== undefined) fs.closeSync(fd); try { fs.unlinkSync(this.lockPath); } catch {} }
  }
  create(message) {
    return this.#locked(() => {
      if (message.idempotencyKey) {
        const existing = [...this.memory.values()].find((m) => m.idempotencyKey === message.idempotencyKey);
        if (existing) return clone(existing);
      }
      message.events ||= [event("message.accepted", message), event("message.queued", message)];
      this.memory.set(message.message_id, clone(message)); this.#commit(); return clone(message);
    });
  }
  get(id) { this.#reload(); return this.memory.has(id) ? clone(this.memory.get(id)) : null; }
  list() { this.#reload(); return [...this.memory.values()].map(clone); }
  findByIdempotencyKey(key) { return key ? this.list().find((m) => m.idempotencyKey === key) || null : null; }
  clear() { return this.#locked(() => { this.memory.clear(); this.#commit(); }); }
  deleteWhere(predicate) { return this.#locked(() => { for (const [id, item] of this.memory) if (predicate(item)) this.memory.delete(id); this.#commit(); }); }
  recordDeliveryEvent({ message_id, transport_message_id, type, recipient, timestamp = iso(), metadata = {} }) {
    return this.#locked(() => {
      const message = [...this.memory.values()].find((item) => item.message_id === message_id ||
        (transport_message_id && item.transport?.message_id === transport_message_id));
      if (!message) return null;
      if (!["delivered", "bounced", "complained"].includes(type)) throw new Error(`Unsupported delivery event: ${type}`);
      if (!(["sent", "delivered"].includes(message.status))) return clone(message);
      const next = { ...message, status: type, [`${type}_at`]: timestamp,
        events: [...(message.events || []), event(`message.${type}`, message, { recipient, metadata })], updated_at: timestamp };
      this.memory.set(next.message_id, next); this.#commit(); return clone(next);
    });
  }
  claimNext(workerId, { leaseMs = 30_000 } = {}) {
    return this.#locked(() => {
      const now = Date.now();
      const candidate = [...this.memory.values()].find((m) => {
        if (!["queued", "leased", "sending", "retrying"].includes(m.status)) return false;
        if (m.next_retry_at && Date.parse(m.next_retry_at) > now) return false;
        return !m.lease_expires_at || Date.parse(m.lease_expires_at) <= now;
      });
      if (!candidate) return null;
      const next = { ...candidate, status: "leased", claimed_by: workerId,
        claim_token: `claim_${randomUUID().replaceAll("-", "")}`,
        lease_expires_at: iso(now + leaseMs), leased_at: iso(now), attempt: (candidate.attempt || 0) + 1,
        attempt_count: (candidate.attempt || 0) + 1, updated_at: iso(now) };
      next.events = [...(next.events || []), event("message.claimed", next), event("message.sending", next)];
      next.status = "sending"; next.sending_at = iso(now);
      this.memory.set(next.message_id, next); this.#commit(); return clone(next);
    });
  }
  async #finish(id, token, mutate) {
    return this.#locked(() => {
      const current = this.memory.get(id);
      if (!current || current.claim_token !== token || Date.parse(current.lease_expires_at) <= Date.now()) {
        throw new MailPortError(ERROR_CODES.MAIL_LEASE_LOST, "Message lease is no longer owned");
      }
      const next = mutate(clone(current)); this.memory.set(id, next); this.#commit(); return clone(next);
    });
  }
  async complete(id, token, result = {}) { return this.#finish(id, token, (m) => ({ ...m, status: "sent", delivery: result,
    transport: { type: result.transport || result.type || null, message_id: result.message_id || null, metadata: result.metadata || {} },
    events: [...(m.events || []), event("message.sent", m, { transport: result.transport || result.type || null })],
    sent_at: iso(), claim_token: null, claimed_by: null, lease_expires_at: null, next_retry_at: null, next_attempt_at: null, updated_at: iso() })); }
  async retry(id, token, result = {}) { return this.#finish(id, token, (m) => ({ ...m, status: "retrying",
    last_error: result.error?.message || result.error || null, next_retry_at: result.nextRetryAt,
    next_attempt_at: result.nextRetryAt, events: [...(m.events || []), event("message.retry_scheduled", m, { error_code: result.error?.code || null })],
    claim_token: null, claimed_by: null, lease_expires_at: null, updated_at: iso() })); }
  async fail(id, token, result = {}) { return this.#finish(id, token, (m) => ({ ...m, status: "failed",
    last_error: result.error?.message || result.error || null, failed_at: iso(), claim_token: null,
    events: [...(m.events || []), event("message.failed", m, { error_code: result.error?.code || null })],
    claimed_by: null, lease_expires_at: null, next_retry_at: null, updated_at: iso() })); }
}

export function createOutbox({ filePath, store } = {}) { return store || new FileMailStore({ filePath }); }

export function createOutboxWorker({ outbox, transport, workerId = `worker_${randomUUID()}`,
  maxAttempts = 5, retryBaseMs = 250, leaseMs = 30_000 } = {}) {
  let running = false; let active = 0;
  let stopping = false;
  return {
    get running() { return running; }, get active() { return active; }, workerId,
    async tick() {
      if (running) return; running = true;
      try {
        while (!stopping) {
          const message = await outbox.claimNext(workerId, { leaseMs });
          if (!message) break;
          active += 1;
          try {
            const result = await transport.send(message);
            if (result?.status === "failed") await outbox.fail(message.message_id, message.claim_token, result);
            else if (result?.status === "retry") await outbox.retry(message.message_id, message.claim_token, { ...result,
              nextRetryAt: iso(Date.now() + retryBaseMs * 2 ** (message.attempt - 1)) });
            else await outbox.complete(message.message_id, message.claim_token, result);
          } catch (error) {
            if (error?.code === ERROR_CODES.MAIL_LEASE_LOST) continue;
            try {
              if (message.attempt >= maxAttempts) await outbox.fail(message.message_id, message.claim_token, { error });
              else await outbox.retry(message.message_id, message.claim_token, { error,
                nextRetryAt: iso(Date.now() + retryBaseMs * 2 ** (message.attempt - 1)) });
            } catch (finishError) { if (finishError?.code !== ERROR_CODES.MAIL_LEASE_LOST) throw finishError; }
          } finally { active -= 1; }
        }
      } finally { running = false; }
    },
    stop() { stopping = true; },
  };
}
