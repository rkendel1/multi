import type { AuthPortClient, AuthPortOptions, AuthProjection } from "./client.js";
export interface ReactLike {
  createContext(defaultValue: unknown): unknown;
  createElement(type: unknown, props: unknown, children: unknown): unknown;
  useContext(context: unknown): any;
  useEffect(effect: () => void | (() => void), dependencies: unknown[]): void;
  useState<T>(initial: T): [T, (next: T) => void];
}
export interface AuthPortReactOptions extends AuthPortOptions { client?: AuthPortClient }
export interface AuthHookValue extends AuthProjection {
  loading: boolean;
  signIn: AuthPortClient["signIn"];
  signOut: AuthPortClient["signOut"];
  authorize: AuthPortClient["authorize"];
  /** Rendering hint only; the server remains authoritative. */
  can: AuthPortClient["can"];
}
export declare function createAuthPortReact(React: ReactLike, options?: AuthPortReactOptions): {
  AuthPort(props: { children?: unknown }): unknown;
  useAuth(): AuthHookValue;
  client: AuthPortClient;
};
