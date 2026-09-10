import { randomUUID } from "node:crypto";
import { MailPortError, ERROR_CODES } from "@mailerport/core";
import { renderTemplate, extractLinks } from "./template-renderer.js";
import { MemoryTransport, LocalTransport } from "./transports.js";
import { createRemoteMailPortClient } from "./remote-client.js";
import { createOutbox, createOutboxWorker } from "./outbox.js";

const DEFAULT_LIMITS = {
  maxAttachmentCount: 10,
  maxAttachmentSizeBytes: 10 * 1024 * 1024,
  maxMessageSizeBytes: 25 * 1024 * 1024,
  maxRecipientCount: 100,
  maxSubjectLength: 998,
  maxTextLength: 5 * 1024 * 1024,
  maxHtmlLength: 10 * 1024 * 1024,
};

function normalizeRecipients(input) {
  if (!input) return [];
  const values = Array.isArray(input) ? input : [input];
  return values.filter(Boolean);
}

function assertRecipients(payload) {
  const all = [
    ...normalizeRecipients(payload.to),
    ...normalizeRecipients(payload.cc),
    ...normalizeRecipients(payload.bcc),
    ...normalizeRecipients(payload.reply_to),
  ];
  if (all.length === 0) {
    throw new MailPortError(
      ERROR_CODES.MAIL_INVALID_RECIPIENT,
      "At least one recipient is required"
    );
  }
}

function assertSafeHeaders(payload, limits) {
  const headers = [payload.subject, payload.from, ...normalizeRecipients(payload.to), ...normalizeRecipients(payload.cc),
    ...normalizeRecipients(payload.bcc), ...normalizeRecipients(payload.reply_to)];
  if (headers.some((value) => /\r|\n/.test(String(value || "")))) {
    throw new MailPortError(ERROR_CODES.MAIL_INVALID_HEADER, "Mail headers cannot contain newlines");
  }
  const recipients = normalizeRecipients(payload.to).length + normalizeRecipients(payload.cc).length + normalizeRecipients(payload.bcc).length;
  if (recipients > limits.maxRecipientCount || String(payload.subject || "").length > limits.maxSubjectLength ||
      String(payload.text || "").length > limits.maxTextLength || String(payload.html || "").length > limits.maxHtmlLength) {
    throw new MailPortError(ERROR_CODES.MAIL_MESSAGE_TOO_LARGE, "Message field exceeds configured limit");
  }
}

function estimateSizeBytes(message) {
  return Buffer.byteLength(JSON.stringify(message), "utf8");
}

function resolveTransportName(explicitTransport, environment = process.env) {
  if (explicitTransport && typeof explicitTransport === "object") {
    if (typeof explicitTransport.send === "function") return "custom";
    if (typeof explicitTransport.kind === "string") return explicitTransport.kind;
  }
  if (!explicitTransport && environment.MAILPORT_URL) return "remote";
  return (
    explicitTransport ||
    environment.FELTDB_MAIL_TRANSPORT ||
    environment.MAILPORT_TRANSPORT ||
    "memory"
  );
}

function createTransport(name, explicitTransport, environment = process.env) {
  if (name === "custom" && explicitTransport && typeof explicitTransport.send === "function") {
    return explicitTransport;
  }
  if (name === "memory") return new MemoryTransport();
  if (name === "local") return new LocalTransport();
  if (name === "smtp") throw new MailPortError(ERROR_CODES.MAIL_NOT_CONFIGURED, "SMTP belongs in @mailerport/smtp and service configuration");
  throw new MailPortError(ERROR_CODES.MAIL_NOT_CONFIGURED, `Unknown transport: ${name}`);
}

function deepClone(value) {
  if (typeof structuredClone === "function") {
    return structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value));
}

export function createMailPort(config) {
  config ||= {};
  const transportName = resolveTransportName(config.transport, config.environment);
  if (transportName === "remote") {
    return createRemoteMailPortClient({
      baseUrl: config.remote?.baseUrl || config.environment?.MAILPORT_URL || process.env.MAILPORT_URL,
      apiKey: config.remote?.apiKey || config.environment?.MAILPORT_API_KEY || process.env.MAILPORT_API_KEY,
      ...(config.remote || {}),
      testEndpointsEnabled: Boolean(config.testEndpointsEnabled),
    });
  }

  const transport = createTransport(transportName, config.transport, config.environment);
  const identities = config.identities || {};
  const templates = config.templates || {};
  const limits = { ...DEFAULT_LIMITS, ...(config.limits || {}) };
  const durableOutboxEnabled = Boolean(config.outbox?.enabled || config.outbox?.filePath);
  const messages = new Map();
  const idempotency = new Map();
  const outbox = durableOutboxEnabled ? createOutbox({ filePath: config.outbox?.filePath }) : null;
  const worker =
    durableOutboxEnabled && config.outbox?.workerEnabled !== false
      ? createOutboxWorker({
          outbox,
          transport,
          maxAttempts: config.outbox?.maxAttempts,
          retryBaseMs: config.outbox?.retryBaseMs,
          leaseMs: config.outbox?.leaseMs,
        })
      : null;
  const pollIntervalMs = config.outbox?.pollIntervalMs || 25;
  let workerTick = Promise.resolve();
  function runWorkerTick() {
    if (!worker) return Promise.resolve();
    workerTick = workerTick
      .catch(() => {})
      .then(() => worker.tick())
      .catch(() => {});
    return workerTick;
  }
  const workerInterval = worker && setInterval(() => void runWorkerTick(), pollIntervalMs);

  const mail = {
    transportName,
    async send(templateOrPayload, maybePayload) {
      const isTemplateSend = typeof templateOrPayload === "string";
      const payload = isTemplateSend ? { ...(maybePayload || {}) } : { ...templateOrPayload };

      if (!payload.identity || (!identities[payload.identity] && !payload.__identityAddress)) {
        throw new MailPortError(
          ERROR_CODES.MAIL_IDENTITY_NOT_FOUND,
          `Unknown identity: ${payload.identity || "(missing)"}`
        );
      }

      if (isTemplateSend) {
        const templateName = templateOrPayload;
        const template = templates[templateName];
        if (!template) {
          throw new MailPortError(
            ERROR_CODES.MAIL_TEMPLATE_NOT_FOUND,
            `Unknown template: ${templateName}`
          );
        }
        payload.template = templateName;
        payload.subject = renderTemplate(template.subject || "", payload.variables);
        payload.html = renderTemplate(template.html || "", payload.variables);
        payload.text = renderTemplate(template.text || "", payload.variables);
      }

      assertRecipients(payload);
      assertSafeHeaders(payload, limits);

      const attachments = payload.attachments || [];
      if (attachments.length > limits.maxAttachmentCount) {
        throw new MailPortError(
          ERROR_CODES.MAIL_MESSAGE_TOO_LARGE,
          "Attachment count exceeds limit"
        );
      }
      for (const attachment of attachments) {
        const content = attachment.content ?? "";
        const contentLength = Buffer.isBuffer(content)
          ? content.length
          : Buffer.byteLength(String(content), "utf8");
        if (contentLength > limits.maxAttachmentSizeBytes) {
          throw new MailPortError(
            ERROR_CODES.MAIL_MESSAGE_TOO_LARGE,
            "Attachment size exceeds limit"
          );
        }
      }

      if (!durableOutboxEnabled && payload.idempotencyKey && idempotency.has(payload.idempotencyKey)) {
        return deepClone(idempotency.get(payload.idempotencyKey));
      }

      const now = new Date().toISOString();
      const messageId = `msg_${randomUUID().replace(/-/g, "")}`;
      const message = {
        message_id: messageId,
        application_id: payload.__applicationId || config.applicationId || "app",
        tenant_id: payload.__tenantId ?? payload.tenantId ?? null,
        identity: payload.identity,
        from: payload.__identityAddress || identities[payload.identity],
        to: normalizeRecipients(payload.to),
        cc: normalizeRecipients(payload.cc),
        bcc: normalizeRecipients(payload.bcc),
        reply_to: normalizeRecipients(payload.reply_to),
        subject: payload.subject || "",
        html: payload.html || "",
        text: payload.text || "",
        template: payload.template || null,
        variables: payload.variables || {},
        metadata: payload.metadata || {},
        idempotencyKey: payload.idempotencyKey || null,
        idempotencyFingerprint: payload.idempotencyKey
          ? JSON.stringify({ ...payload, idempotencyKey: undefined })
          : null,
        attachments,
        dkim: payload.__dkim || null,
        status: "accepted",
        accepted_at: now,
        created_at: now,
        updated_at: now,
      };

      if (estimateSizeBytes(message) > limits.maxMessageSizeBytes) {
        throw new MailPortError(
          ERROR_CODES.MAIL_MESSAGE_TOO_LARGE,
          "Message size exceeds limit"
        );
      }

      if (durableOutboxEnabled) {
        const existing = payload.idempotencyKey
          ? outbox.findByIdempotencyKey(payload.idempotencyKey)
          : null;
        if (existing) {
          if (existing.idempotencyFingerprint !== message.idempotencyFingerprint) {
            throw new MailPortError(ERROR_CODES.MAIL_IDEMPOTENCY_CONFLICT, "Idempotency key was used for a different message");
          }
          return deepClone(existing);
        }

        message.status = "queued";
        message.queued_at = new Date().toISOString();
        message.attempt = 0;
        message.next_retry_at = null;
        message.claim_token = null;
        message.claimed_by = null;
        message.lease_expires_at = null;
        message.updated_at = new Date().toISOString();
        message.links = extractLinks({ html: message.html, text: message.text });
        const persisted = outbox.create(message);
        if (persisted.idempotencyFingerprint !== message.idempotencyFingerprint) {
          throw new MailPortError(ERROR_CODES.MAIL_IDEMPOTENCY_CONFLICT, "Idempotency key was used for a different message");
        }
        if (payload.idempotencyKey) {
          idempotency.set(payload.idempotencyKey, message);
        }
        if (worker) {
          runWorkerTick();
        }
        return deepClone(persisted);
      }

      messages.set(messageId, message);
      message.status = "queued";
      message.updated_at = new Date().toISOString();

      try {
        const delivery = await transport.send(message);
        message.status = delivery.status || "sent";
      } catch (error) {
        message.status = "failed";
        message.last_error = error.message;
        message.updated_at = new Date().toISOString();
        if (error instanceof MailPortError) {
          error.details = { ...(error.details || {}), message_id: message.message_id };
          throw error;
        }
        throw new MailPortError(ERROR_CODES.MAIL_DELIVERY_FAILED, error.message, {
          message_id: message.message_id,
        });
      }
      message.updated_at = new Date().toISOString();
      message.links = extractLinks({ html: message.html, text: message.text });

      if (payload.idempotencyKey) {
        idempotency.set(payload.idempotencyKey, message);
      }

      return deepClone(message);
    },
    get(messageId) {
      if (durableOutboxEnabled) {
        const message = outbox.get(messageId);
        return message ? deepClone(message) : null;
      }
      const message = messages.get(messageId);
      return message ? deepClone(message) : null;
    },
    list(filters = {}) {
      let items = durableOutboxEnabled ? outbox.list() : [...messages.values()];
      if (Object.hasOwn(filters, "to")) {
        items = items.filter((m) => m.to.includes(filters.to));
      }
      if (Object.hasOwn(filters, "subject")) {
        items = items.filter((m) =>
          m.subject.toLowerCase().includes(String(filters.subject).toLowerCase())
        );
      }
      if (Object.hasOwn(filters, "template")) {
        items = items.filter((m) => m.template === filters.template);
      }
      if (Object.hasOwn(filters, "testRunId")) {
        items = items.filter((m) => m.metadata?.testRunId === filters.testRunId);
      }
      if (Object.hasOwn(filters, "status")) {
        items = items.filter((m) => m.status === filters.status);
      }
      return items.map(deepClone);
    },
    test: {
      list(filters = {}) {
        if (!config.testEndpointsEnabled) {
          throw new MailPortError(
            ERROR_CODES.MAIL_TEST_TRANSPORT_DISABLED,
            "Test API is disabled"
          );
        }
        return mail.list(filters);
      },
      get(messageId) {
        if (!config.testEndpointsEnabled) {
          throw new MailPortError(
            ERROR_CODES.MAIL_TEST_TRANSPORT_DISABLED,
            "Test API is disabled"
          );
        }
        return mail.get(messageId);
      },
      async clear(filters = null) {
        if (!config.testEndpointsEnabled) {
          throw new MailPortError(
            ERROR_CODES.MAIL_TEST_TRANSPORT_DISABLED,
            "Test API is disabled"
          );
        }
        const matches = (item) => !filters || Object.entries(filters).every(([key, value]) =>
          key === "testRunId" ? item.metadata?.testRunId === value : item[key] === value);
        for (const [id, item] of messages) if (matches(item)) messages.delete(id);
        if (!filters) idempotency.clear();
        if (durableOutboxEnabled) {
          if (filters && typeof outbox.deleteWhere === "function") outbox.deleteWhere(matches);
          else await outbox.clear();
        }
      },
      async waitFor({ timeoutMs = 5000, intervalMs = 25, ...filters } = {}) {
        if (!config.testEndpointsEnabled) {
          throw new MailPortError(
            ERROR_CODES.MAIL_TEST_TRANSPORT_DISABLED,
            "Test API is disabled"
          );
        }
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
          const found = (await mail.list(filters))[0];
          if (found) return found;
          await new Promise((resolve) => setTimeout(resolve, intervalMs));
        }
        return null;
      },
    },
    async status() {
      const items = durableOutboxEnabled ? outbox.list() : [...messages.values()];
      const count = (status) => items.filter((m) => m.status === status).length;
      const queued = items.filter((m) => ["queued", "retrying"].includes(m.status));
      const transportAttempts = items.reduce((total, item) => total + (item.attempt_count || item.attempt || 0), 0);
      const latencies = items.filter((item) => item.sent_at).map((item) => Date.parse(item.sent_at) - Date.parse(item.accepted_at || item.created_at));
      return { transport: transportName, worker: { running: Boolean(worker), active: worker?.active || 0 },
        volume: { accepted: items.length, sent: count("sent"), delivered: count("delivered"), bounced: count("bounced"), failed: count("failed") },
        outbox: { queued: count("queued"), retrying: count("retrying"), leased: count("leased") + count("sending"),
          failed: count("failed"), oldest_queued_age_ms: queued.length ? Date.now() - Math.min(...queued.map((item) => Date.parse(item.queued_at || item.created_at))) : 0 },
        delivery: { attempts: transportAttempts, successes: items.filter((item) => ["sent", "delivered", "bounced"].includes(item.status)).length,
          failures: count("failed"), average_latency_ms: latencies.length ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : null } };
    },
    recordDeliveryEvent(event) {
      if (!durableOutboxEnabled || typeof outbox.recordDeliveryEvent !== "function") return null;
      return outbox.recordDeliveryEvent(event);
    },
    async close() {
      worker?.stop();
      if (workerInterval) {
        clearInterval(workerInterval);
      }
      await workerTick;
    },
    stopWorker() { worker?.stop(); if (workerInterval) clearInterval(workerInterval); },
  };

  if (workerInterval && typeof workerInterval.unref === "function") {
    workerInterval.unref();
  }

  return mail;
}
