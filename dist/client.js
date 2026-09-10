const ANONYMOUS_VALUE = {
  authenticated: false,
  principal: null,
  tenant: null,
  claims: {},
  capabilities: [],
  session: null,
  delegation: null,
};

export const ANONYMOUS = Object.freeze(ANONYMOUS_VALUE);

/** Create a dependency-free projection of the AuthPort server authority. */
export function createAuthPort(options = {}) {
  const baseUrl = (options.baseUrl || "").replace(/\/$/, "");
  const fetchImpl = options.fetch || globalThis.fetch;
  if (!fetchImpl) throw new Error("AuthPort: no fetch implementation available");

  let state = { loading: true, auth: ANONYMOUS };
  const listeners = new Set();
  const publish = (next) => {
    state = next;
    listeners.forEach((listener) => listener(state));
    return state;
  };
  const call = async (path, init = {}) => {
    const response = await fetchImpl(baseUrl + path, {
      credentials: "include",
      ...init,
      headers: { "content-type": "application/json", ...(init.headers || {}) },
    });
    const text = await response.text();
    let body = {};
    try { body = text ? JSON.parse(text) : {}; }
    catch { body = { error: "invalid_response", message: text }; }
    return { ok: response.ok, status: response.status, body };
  };

  const session = async () => {
    const { ok, body } = await call("/auth/session", { method: "GET" });
    return publish({ loading: false, auth: ok && body.authenticated ? body : ANONYMOUS }).auth;
  };
  const providers = async () => {
    const { body } = await call("/auth/providers", { method: "GET" });
    return body.providers || [];
  };
  const signIn = async (credentials = {}) => {
    const { ok, status, body } = await call("/auth/sign-in", {
      method: "POST", body: JSON.stringify(credentials),
    });
    if (!ok) {
      publish({ loading: false, auth: ANONYMOUS });
      const error = new Error(body.message || "sign-in failed");
      error.status = status;
      error.reason = body.reason;
      throw error;
    }
    return publish({ loading: false, auth: body }).auth;
  };
  const signOut = async () => {
    await call("/auth/sign-out", { method: "POST" });
    return publish({ loading: false, auth: ANONYMOUS }).auth;
  };
  const authorize = async (capability) => {
    const { ok, body } = await call("/auth/authorize", {
      method: "POST", body: JSON.stringify({ capability }),
    });
    return Boolean(ok && body.allowed);
  };
  // Rendering hint only. The server must authorize every protected operation.
  const can = (capability) => (state.auth.capabilities || []).includes(capability);
  const subscribe = (listener) => {
    listeners.add(listener);
    listener(state);
    return () => listeners.delete(listener);
  };

  return {
    get state() { return state; },
    get auth() { return state.auth; },
    session, providers, signIn, signOut, authorize, can, subscribe, ANONYMOUS,
  };
}
