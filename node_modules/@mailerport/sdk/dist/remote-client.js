import { MailPortError, ERROR_CODES } from "@mailerport/core";

function toQueryString(filters = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined) {
      params.set(key, "undefined");
      continue;
    }
    if (value === null) {
      params.set(key, "null");
      continue;
    }
    params.set(key, String(value));
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

async function parseResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ? await response.json() : null;
  if (response.ok) return body;
  const code = body?.error || ERROR_CODES.MAIL_DELIVERY_FAILED;
  throw new MailPortError(code, body?.message || `Request failed with status ${response.status}`, {
    status: response.status,
  });
}

function authHeaders(apiKey) {
  if (!apiKey) return {};
  return { authorization: "Bearer ".concat(apiKey) };
}

export function createRemoteMailPortClient({
  baseUrl,
  apiKey,
  testEndpointsEnabled = false,
} = {}) {
  if (!baseUrl) {
    throw new MailPortError(ERROR_CODES.MAIL_NOT_CONFIGURED, "Missing remote baseUrl");
  }

  async function request(path, options = {}) {
    const response = await fetch(`${baseUrl}${path}`, {
      ...options,
      headers: {
        "content-type": "application/json",
        ...authHeaders(apiKey),
        ...(options.headers || {}),
      },
    });
    return parseResponse(response);
  }

  const client = {
    transportName: "remote",
    async send(templateOrPayload, maybePayload) {
      const body =
        typeof templateOrPayload === "string"
          ? { template: templateOrPayload, payload: maybePayload || {} }
          : templateOrPayload;
      return request("/v1/messages", {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    async get(messageId) {
      return request(`/v1/messages/${encodeURIComponent(messageId)}`);
    },
    async list(filters = {}) {
      return request(`/v1/messages${toQueryString(filters)}`);
    },
    async status() { return request("/v1/status"); },
    operations: {
      domains: { list: () => request("/v1/domains"), get: (domain) => request(`/v1/domains/${encodeURIComponent(domain)}`),
        add: (domain) => request("/v1/domains", { method: "POST", body: JSON.stringify({ domain }) }),
        verify: (domain) => request(`/v1/domains/${encodeURIComponent(domain)}/verify`, { method: "POST" }),
        remove: (domain) => request(`/v1/domains/${encodeURIComponent(domain)}`, { method: "DELETE" }) },
      identities: { list: () => request("/v1/identities"), add: (identity) => request("/v1/identities", { method: "POST", body: JSON.stringify(identity) }) },
      suppressions: { list: () => request("/v1/suppressions"), add: (suppression) => request("/v1/suppressions", { method: "POST", body: JSON.stringify(suppression) }) },
      events: (messageId) => request(`/v1/messages/${encodeURIComponent(messageId)}/events`),
    },
    test: {
      async list(filters = {}) {
        if (!testEndpointsEnabled) {
          throw new MailPortError(
            ERROR_CODES.MAIL_TEST_TRANSPORT_DISABLED,
            "Test API is disabled"
          );
        }
        return request(`/v1/test/messages${toQueryString(filters)}`);
      },
      async get(messageId) {
        if (!testEndpointsEnabled) {
          throw new MailPortError(
            ERROR_CODES.MAIL_TEST_TRANSPORT_DISABLED,
            "Test API is disabled"
          );
        }
        return request(`/v1/test/messages/${encodeURIComponent(messageId)}`);
      },
      async clear() {
        if (!testEndpointsEnabled) {
          throw new MailPortError(
            ERROR_CODES.MAIL_TEST_TRANSPORT_DISABLED,
            "Test API is disabled"
          );
        }
        return request("/v1/test/messages", { method: "DELETE" });
      },
      async waitFor({ timeoutMs = 5000, intervalMs = 25, ...filters } = {}) {
        if (!testEndpointsEnabled) {
          throw new MailPortError(
            ERROR_CODES.MAIL_TEST_TRANSPORT_DISABLED,
            "Test API is disabled"
          );
        }
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
          const found = (await request(`/v1/test/messages${toQueryString(filters)}`))[0];
          if (found) return found;
          await new Promise((resolve) => setTimeout(resolve, intervalMs));
        }
        return null;
      },
    },
    close() {},
  };

  return client;
}
