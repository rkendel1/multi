import type { AuthBoundryClient, AuthBoundryOptions, AuthProjection } from "./client.js";
export interface ReactLike {
  createContext(defaultValue: unknown): unknown;
  createElement(type: unknown, props: unknown, children: unknown): unknown;
  useContext(context: unknown): any;
  useEffect(effect: () => void | (() => void), dependencies: unknown[]): void;
  useState<T>(initial: T): [T, (next: T) => void];
}
export interface AuthBoundryReactOptions extends AuthBoundryOptions { client?: AuthBoundryClient }
export interface AuthHookValue extends AuthProjection {
  loading: boolean;
  signIn: AuthBoundryClient["signIn"];
  signOut: AuthBoundryClient["signOut"];
  authorize: AuthBoundryClient["authorize"];
  /** Rendering hint only; the server remains authoritative. */
  can: AuthBoundryClient["can"];
}
export declare function createAuthBoundryReact(React: ReactLike, options?: AuthBoundryReactOptions): {
  AuthBoundry(props: { children?: unknown }): unknown;
  useAuth(): AuthHookValue;
  client: AuthBoundryClient;
};
