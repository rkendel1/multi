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
export interface AuthPortState { loading: boolean; auth: AuthProjection }
export interface AuthPortOptions {
  baseUrl?: string;
  fetch?: typeof fetch;
}
export interface AuthPortClient {
  readonly state: AuthPortState;
  readonly auth: AuthProjection;
  session(): Promise<AuthProjection>;
  providers(): Promise<unknown[]>;
  signIn(credentials?: Record<string, unknown>): Promise<AuthProjection>;
  signOut(): Promise<AuthProjection>;
  authorize(capability: string): Promise<boolean>;
  /** Rendering hint only; the server remains authoritative. */
  can(capability: string): boolean;
  subscribe(listener: (state: AuthPortState) => void): () => void;
  readonly ANONYMOUS: AuthProjection;
}
export declare const ANONYMOUS: Readonly<AuthProjection>;
export declare function createAuthPort(options?: AuthPortOptions): AuthPortClient;
