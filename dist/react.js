import { createAuthBoundry } from "./client.js";

/** Create React bindings without making React a runtime dependency. */
export function createAuthBoundryReact(React, options = {}) {
  const client = options.client || createAuthBoundry(options);
  const Context = React.createContext(null);

  function AuthBoundry(props) {
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
    if (!value) throw new Error("useAuth() must be used inside <AuthBoundry>");
    return value;
  }
  return { AuthBoundry, useAuth, client };
}
