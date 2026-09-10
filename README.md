# AuthPort

AuthPort is the authority boundary for an application.

Embed it when you own the application server. Run it in front of the application
when you don't. Either way the application gets the same identity, tenancy,
authorization, agent, delegation and session model — and the developer
integrates AuthPort once.

```sh
npm install authboundry
npx authport --help
```

```
use auth {
  providers = [google, github, email]

  tenant = true

  claims = {
    role = enum["owner", "admin", "member"]
    plan = enum["free", "pro"]
  }

  agents = true
}
```

From that declaration AuthPort derives the identity model, sessions, tenancy,
authorization, the agent and delegation model, the HTTP surface and the default
UI. The application never declares session tables, user tables, token storage,
provider middleware, callback plumbing, authorization middleware, email delivery
or tenant lookup.

Humans and agents are both first-class principals under one authority model. An
agent is not a user with a special role.

## The boundary

```
request
  |
  v
credential -> AuthPort -> principal -> tenant -> claims
                              |
                        delegation -> capabilities -> authorization
                                                          |
                                                          v
                                                application handler
```

Everything a client sends is a hint. The authoritative principal, tenant,
claims and capabilities are reconstructed from AuthPort's own state, which is
why a browser cannot argue its way into authority:

```
client says:  principal = Alice, capability = billing.charge
server says:  no
```

The core interface is framework-neutral — no Axum, Express or FastAPI in the
authority model:

```rust
pub trait AuthBoundary {
    fn authenticate(&self, request: &BoundaryRequest) -> Result<AuthContext, AuthError>;
    fn authorize(&self, context: &AuthContext, capability: &str)
        -> Result<AuthorizationDecision, AuthError>;
}
```

## Storage, audit and reporting

AuthPort owns the meaning and integrity of authority data, not the customer's
database choice. The auth contract may name storage providers by capability:

```rust
use auth {
  providers = [google, github, email]
  storage {
    authority = "feltdb"
    audit = "feltdb"
  }
}
```

Connection strings, credentials and database-specific deployment details stay
outside the application authority contract. The storage boundary is split by
semantics — identity, tenants, sessions, credentials, policies, delegations,
agents, runs, audit and reporting — so deployments can place different classes
of data in FeltDB, PostgreSQL, enterprise systems or customer-owned stores.
FeltDB is the zero-setup default and reference native substrate; PostgreSQL is
represented by the same storage conformance contract rather than a different
authority model.

Audit is a durable, append-oriented authority stream, not application logging.
Required authority/security audit failures fail closed, while external audit
sinks and reporting projections are non-authoritative integrations. The control
plane exposes storage and audit status without secrets:

```
GET /_authport/storage
GET /_authport/storage/capabilities
GET /_authport/audit
GET /_authport/audit/events?tenant=acme
GET /_authport/audit/export?tenant=acme
GET /_authport/reporting
```

`authport audit export --tenant acme` returns canonical JSON Lines suitable for
enterprise export.

`AuthContext` has no public constructor. Outside the boundary crate you can read
one, never build one: it exists because AuthPort verified a request.

## Two placements, one model

```
AuthPort Runtime
|
+-- Embedded      bound to the application's server
|
+-- Standalone    owns the server; the application sits behind it
```

Embedded — handlers run in the same process, and the boundary resolves authority
before one is ever called:

```rust
let server = AuthPortServer::new(
    runtime,
    Arc::new(
        RouterApp::new()
            .public(Method::Get, "/public", handler)
            .authenticated(Method::Get, "/profile", handler)
            .require(Method::Get, "/invoices", "invoice.read", handler)
            .require(Method::Post, "/invoices", "invoice.create", handler),
    ),
);
```

Standalone — AuthPort owns the socket, authenticates, and forwards the derived
context to an application that implements no authentication at all:

```
Browser -> AuthPort -> Example Application
```

```
authport serve --addr 127.0.0.1:8787 \
  --tenant acme --account alice:secret:role=owner,plan=pro \
  --grant invoice.read=role:owner \
  --upstream 127.0.0.1:9000 --public /health
```

Inbound `x-authport-*` headers are stripped before the request is looked at, and
a path with no route policy is refused rather than forwarded.

## The generated HTTP surface

Derived from the contract, not hand-mounted:

```
POST   /auth/login      (also /auth/sign-in)     GET renders the default UI
POST   /auth/signup                              closed unless the deployment opens it
POST   /auth/logout     (also /auth/sign-out)
GET    /auth/session                             the client projection
GET    /auth/providers
POST   /auth/authorize                           the server's answer, not the client's
GET    /auth/tenant, /auth/tenants               when tenancy is declared
GET    /auth/agents, /auth/delegations           when agents are declared
```

## The client

The browser side is a projection of server authority, never the security
mechanism:

```js
import { createAuthPort } from "authboundry";

const authport = createAuthPort();
const auth = await authport.session();
await authport.authorize("invoice.create"); // asks the authority boundary
```

The same client has an optional React adapter; React is supplied by the host
application and is not installed as an AuthPort dependency:

```js
import { createAuthPortReact } from "authboundry/react";

const { AuthPort, useAuth } = createAuthPortReact(React);

// <AuthPort><App /></AuthPort>

const auth = useAuth();
auth.principal;  auth.tenant;  auth.claims;  auth.capabilities;  auth.session;
await auth.signIn({ tenant: "acme", connector: "local", username, password });
await auth.authorize("invoice.create");   // asks the server
auth.can("invoice.create");               // rendering hint only
```

The `authboundry/client` entry point is dependency-free and build-step-free. The
generated sign-in page and npm client speak the same server-derived HTTP
contract; neither can establish authority independently.

## Inspecting a contract

```
$ authport inspect examples/saas_basic/appport.auth

AuthPort · Auth
────────────────────────

Multi-tenant: yes
Isolation: strict
Contract: cd3a693ead706fb2
Surface: 898d494c0619d131

Providers:
  ✓ local

Claims:
  billing: manager | none
  plan: free | pro
  role: admin | member | owner

Principals:
  human
  agent
  service

Agents:
  enabled

Delegation:
  enabled

Runtime boundary:
  contract: authport.boundary/v1
  modes: embedded, standalone
  session credential: cookie:authport_session

Generated surfaces:
  /auth/login  (also /auth/sign-in)
  ...
```

`authport` also has `serve`, `fingerprint`, `routes`, `providers` and
`inspect --json [--mode embedded|standalone]`. Semantically identical
declarations produce the same canonical contract and the same fingerprint.

## Crates

| Crate | Responsibility |
| --- | --- |
| `contract` | Principals, tenants, identities, claims, delegations, ids |
| `dsl` | `use auth { ... }`, canonicalization, contract fingerprint |
| `providers` | Connector contract, catalog and registry |
| `surface` | `AuthSurface` derivation, inspection, UI and boundary contract |
| `storage` | Storage boundary, tenant roots, identities, principals, sessions, delegations, runs, audit, reporting/export |
| `authz` | Policy evaluation and capability provenance |
| `runtime` | `AuthMesh`: authentication, resolution, sessions, delegation |
| `boundary` | `AuthPortRuntime`, `AuthContext`, `AuthBoundary`, binding modes |
| `server` | The HTTP surface, the embedded router, the standalone proxy, the UI |
| `cli` | `authport` |

## Security posture

Everything fails closed — missing credential, invalid, expired or revoked
session, unknown tenant or principal, wrong tenant, revoked agent, expired or
revoked delegation, ungranted capability, missing policy, missing claim,
unsupported connector, a path with no route policy, and a decision that cannot
be audited. There is no fallback authentication, no implicit tenant, no
anonymous escalation, and no capability inferred from provider identity alone.

The full invariant list, with the tests that hold each one, is in
[docs/architecture.md](docs/architecture.md).

## Production status

Production OAuth (Google, GitHub, Microsoft, Apple), SAML, SCIM, MFA, passkeys,
password reset, production email delivery, production key infrastructure,
Postgres, Redis, distributed sessions, a polished component library, TLS
termination and production proxy features. The local connector's credential
digest, the session id source and the proxy's context signature are development
mechanisms, documented as such in `docs/architecture.md`.

Version 1.0.0 stabilizes the JavaScript projection and packaged CLI surface; it
does not mean those integrations are production-ready. The packaged native CLI
runtime currently supports macOS on Apple silicon. Other platforms can use the
JavaScript client, but `npx authport` will report that no native runtime is
packaged.

## Running

```
cargo test --workspace                 # 78 tests
node --test clients/js/authport.test.js

cargo run -p saas_basic                # both modes, side by side
cargo run -p saas_basic -- serve       # standalone: browser -> AuthPort -> app
cargo run -p saas_basic -- embedded    # AuthPort bound to the app's own server
cargo run -p appport-auth-mesh-cli -- inspect examples/saas_basic/appport.auth
```

`examples/saas_basic` is the reference application: Alice (owner, tenant A) can
read and create invoices but cannot charge billing; she delegates invoice
capabilities to an invoice agent that authenticates through the same boundary
and cannot exceed them; Bob is isolated in tenant B; revoking the delegation,
the agent or the session removes authority immediately. Its entire auth
integration is one file.
