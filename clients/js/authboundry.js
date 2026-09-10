/**
 * The AuthBoundry client.
 *
 * This is a projection of server authority, never the security mechanism.
 * Everything it exposes was decided by the backend boundary; editing any of it
 * in a browser changes what the page renders and nothing about what the server
 * permits.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.AuthBoundry = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  const ANONYMOUS = Object.freeze({
    authenticated: false,
    principal: null,
    tenant: null,
    claims: {},
    capabilities: [],
    session: null,
    delegation: null,
  });

  function createAuthBoundry(options) {
    const settings = options || {};
    const baseUrl = (settings.baseUrl || "").replace(/\/$/, "");
    const fetchImpl = settings.fetch || (typeof fetch !== "undefined" ? fetch : null);
    if (!fetchImpl) {
      throw new Error("AuthBoundry: no fetch implementation available");
    }

    let state = { loading: true, auth: ANONYMOUS };
    const listeners = new Set();

    function publish(next) {
      state = next;
      listeners.forEach((listener) => listener(state));
      return state;
    }

    async function call(path, init) {
      const response = await fetchImpl(baseUrl + path, {
        credentials: "include",
        ...init,
        headers: { "content-type": "application/json", ...((init || {}).headers || {}) },
      });
      const text = await response.text();
      let body = {};
      try {
        body = text ? JSON.parse(text) : {};
      } catch (error) {
        body = { error: "invalid_response", message: text };
      }
      return { ok: response.ok, status: response.status, body };
    }

    /** Ask the server who this browser is. The answer is the only truth. */
    async function session() {
      const { ok, body } = await call("/auth/session", { method: "GET" });
      return publish({ loading: false, auth: ok && body.authenticated ? body : ANONYMOUS }).auth;
    }

    async function providers() {
      const { body } = await call("/auth/providers", { method: "GET" });
      return body.providers || [];
    }

    async function signIn(credentials) {
      const { ok, status, body } = await call("/auth/sign-in", {
        method: "POST",
        body: JSON.stringify(credentials || {}),
      });
      if (!ok) {
        publish({ loading: false, auth: ANONYMOUS });
        const error = new Error(body.message || "sign-in failed");
        error.status = status;
        error.reason = body.reason;
        throw error;
      }
      return publish({ loading: false, auth: body }).auth;
    }

    async function signOut() {
      await call("/auth/sign-out", { method: "POST" });
      return publish({ loading: false, auth: ANONYMOUS }).auth;
    }

    /**
     * Ask the server whether this principal may do something.
     *
     * Use this for anything that matters. `can()` below is a rendering hint
     * drawn from the same projection, and the server re-decides regardless.
     */
    async function authorize(capability) {
      const { ok, body } = await call("/auth/authorize", {
        method: "POST",
        body: JSON.stringify({ capability }),
      });
      return Boolean(ok && body.allowed);
    }

    function can(capability) {
      return (state.auth.capabilities || []).indexOf(capability) !== -1;
    }

    function subscribe(listener) {
      listeners.add(listener);
      listener(state);
      return () => listeners.delete(listener);
    }

    return {
      get state() {
        return state;
      },
      get auth() {
        return state.auth;
      },
      session,
      providers,
      signIn,
      signOut,
      authorize,
      can,
      subscribe,
      ANONYMOUS,
    };
  }

  /**
   * React binding, created against whichever React the host app already has,
   * so this file stays dependency-free and build-step-free.
   *
   *   const { AuthBoundry, useAuth } = createAuthBoundryReact(React);
   *   <AuthBoundry><App /></AuthBoundry>
   */
  function createAuthBoundryReact(React, options) {
    const client = (options && options.client) || createAuthBoundry(options);
    const Context = React.createContext(null);

    function AuthBoundryProvider(props) {
      const [state, setState] = React.useState(client.state);
      React.useEffect(() => {
        const unsubscribe = client.subscribe(setState);
        client.session().catch(() => {});
        return unsubscribe;
      }, []);

      const value = {
        loading: state.loading,
        principal: state.auth.principal,
        tenant: state.auth.tenant,
        claims: state.auth.claims,
        capabilities: state.auth.capabilities,
        session: state.auth.session,
        delegation: state.auth.delegation,
        authenticated: state.auth.authenticated,
        signIn: client.signIn,
        signOut: client.signOut,
        authorize: client.authorize,
        can: client.can,
      };

      return React.createElement(Context.Provider, { value }, props.children);
    }

    function useAuth() {
      const value = React.useContext(Context);
      if (!value) {
        throw new Error("useAuth() must be used inside <AuthBoundry>");
      }
      return value;
    }

    return { AuthBoundry: AuthBoundryProvider, useAuth, client };
  }

  return { createAuthBoundry, createAuthBoundryReact, ANONYMOUS };
});
