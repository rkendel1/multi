export interface Principal { id: string; kind: string; [key: string]: unknown }
export interface Tenant { id: string; [key: string]: unknown }
export interface Session { [key: string]: unknown }
export interface Delegation { [key: string]: unknown }
export interface AuthProjection {
  authenticated: boolean;
  principal: Principal | null;
  tenant: Tenant | null;
  claims: Record<string, unknown>;
  capabilities: string[];
  session: Session | null;
  delegation: Delegation | null;
}
export interface AuthBoundryState { loading: boolean; auth: AuthProjection }
export interface AuthBoundryOptions {
  baseUrl?: string;
  fetch?: typeof fetch;
  tenant?: string;
  connector?: string;
}
export interface AuthBoundryClient {
  readonly state: AuthBoundryState;
  readonly auth: AuthProjection;
  session(): Promise<AuthProjection>;
  providers(): Promise<unknown[]>;
  signIn(credentials?: Record<string, unknown>): Promise<AuthProjection>;
  signOut(): Promise<AuthProjection>;
  authorize(capability: string): Promise<boolean>;
  /** Rendering hint only; the server remains authoritative. */
  can(capability: string): boolean;
  subscribe(listener: (state: AuthBoundryState) => void): () => void;
  readonly ANONYMOUS: AuthProjection;
}
export declare const ANONYMOUS: Readonly<AuthProjection>;
export declare function createAuthBoundry(options?: AuthBoundryOptions): AuthBoundryClient;
