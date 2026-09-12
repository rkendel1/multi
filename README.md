# AuthBoundry

The authority boundary for an application.

AuthBoundry turns identity, tenancy, authorization, delegation, sessions,
humans, agents and services into one authoritative model. Use it inside an
application you own, or place it in front of an application you cannot modify.
Declare the authority model once. AuthBoundry derives and enforces the boundary.

```text
Browser -> AuthBoundry -> Application

┌──────────────────────────────────┐
│            AuthBoundry           │
│ identity       tenancy           │
│ claims         sessions          │
│ delegation     capabilities      │
│ authorization  agents      audit │
└──────────────────────────────────┘
                 |
                 v
            Application
```

Your application should not have to implement its own authority system.

## Quick start

```sh
npm install @authboundry/core
npx authboundry init
npx authboundry studio
npx authboundry status
npx authboundry inspect app.auth
```

The first example is an authority declaration:

```text
use auth {
  providers = [google, github, email]
  tenant = true
  claims = {
    role = enum["owner", "admin", "member"]
    plan = enum["free", "pro"]
  }
  agents = true
}

use mail
mail {
  identities { auth = "auth@example.com" }
  templates {
    password_reset = "./emails/password-reset.html"
    email_verification = "./emails/email-verification.html"
  }
}
```

This declares the application's authority model. AuthBoundry derives its
identity and tenant models, claims, sessions, delegation, agent principals,
authorization and HTTP surfaces, client projection and default UI. A declared
connector is available only when its implementation exists.

Password recovery and email verification cross the MailPort boundary. Configure
the MailPort origin with `MAILPORT_URL` and, when required, its bearer credential
with `MAILPORT_API_KEY`. Recovery requests always return the same accepted
response; reset and verification links use short-lived, opaque, hashed-at-rest,
single-use challenges.

```text
declare authority -> inspect authority -> run AuthBoundry -> connect application
```

`init` creates an authority configuration and adoption record. It does not
claim the application is attached. When automatic attachment is unavailable,
start the application and explicitly record its reachable target:

```sh
npx authboundry attach --upstream http://127.0.0.1:9000
npx authboundry serve
```

`status` distinguishes configured, running, attached and actively protected
states. A configuration file alone means only **configured**.

Interactive initialization starts Studio automatically. Use
`authboundry studio --no-open` for CI or headless environments. Studio reads
the contract and adoption record; repository changes still require an explicit
CLI preview and human approval.

## Why an authority boundary?

Applications traditionally assemble authority from an identity provider,
session middleware, user, tenant and membership tables, roles, permission
checks, service accounts, API keys, agent identities, delegation and audit.
Authority becomes distributed throughout application code.

The application then answers: Who is this? Which tenant? Which permissions? Can
this service or agent act? Who delegated the capability? Was it revoked?
AuthBoundry moves those questions to one authoritative boundary. The application
receives an already-derived authority context.

```text
request -> credential -> AuthBoundry
                           |-> principal
                           |-> tenant
                           |-> claims
                           |-> delegation
                           |-> capabilities
                           v
                  authorization decision -> application
```

Authentication answers “Who are you?” AuthBoundry answers who is acting, for
which tenant, under whose delegation, with which capabilities, and whether the
request is authorized. Identity providers are connectors into the boundary;
they do not define the application's authority model.

```text
Your application -> asks AuthBoundry -> “Is X authorized?”
                         |
                         v
              AuthBoundry derives the answer -> handler
```

Everything a client supplies is a hint. The boundary reconstructs authority
from verified state rather than accepting client claims.

## One authority model. Two boundaries.

```text
Embedded                       Standalone
Application Server             Browser
       |                           |
   AuthBoundry                  AuthBoundry
       |                           |
   Application              Existing Application
```

The placement changes. The authority model does not.

Embedded mode binds the boundary to an application-owned server. Standalone
mode owns the socket, authenticates and authorizes requests, strips inbound
`x-authboundry-*` authority headers, and forwards only explicitly governed routes.
See [embedded](docs/deployment/embedded.md) and
[standalone](docs/deployment/standalone.md) deployment.

## Protect an application without rewriting it

An existing application can remain unaware of providers, sessions, user
databases, tenant resolution, authorization middleware, delegation and agent
identity. AuthBoundry can establish the authority boundary in front of it.

```text
                  AuthBoundry
                 /           \
           authenticate    authorize
                 \           /
                  Existing App
```

```sh
npx authboundry serve app.auth \
  --tenant acme --account alice:secret:role=owner@acme \
  --grant invoice.create=role:owner \
  --upstream 127.0.0.1:9000 --public /health
```

The local account and in-memory storage mechanisms are development references.

## Humans and agents are principals

An agent is not a user with a special role. Humans, agents and services are
first-class principals, and delegated execution is explicit.

```text
Human -> delegates -> Agent -> invokes -> Capability -> Application

delegation granted -> agent authorized -> delegation revoked -> agent denied

Alice
  |-- invoice.read
  |-- invoice.create
  `-- delegates invoice.create -> Invoice Agent

Invoice Agent
  |-- invoice.create   ✓
  `-- billing.charge   ✗
```

Delegation cannot grant authority the delegating principal does not possess.
Revocation removes delegated authority at the boundary.

## The client is a projection

The browser client projects what the server decided. It cannot manufacture an
authority context.

```js
import { createAuthBoundry } from "@authboundry/core";

const client = createAuthBoundry();
const auth = await client.session();
auth.principal; auth.tenant; auth.claims; auth.capabilities; auth.session;
await client.authorize("invoice.create"); // asks the server
client.can("invoice.create");             // UI rendering hint only
```

```js
import { createAuthBoundryReact } from "@authboundry/core/react";
const { AuthBoundry, useAuth } = createAuthBoundryReact(React);
// <AuthBoundry><App /></AuthBoundry>
```

The server remains authoritative.

## The boundary is authoritative

```text
client:       principal=Alice tenant=acme capability=billing.charge
AuthBoundry:  No.

credential -> verified session -> principal -> tenant -> claims
    -> delegation -> capabilities -> authorization
```

AuthBoundry denies missing or invalid credentials; expired or revoked sessions;
unknown or wrong tenants; revoked agents; expired or revoked delegations;
ungranted capabilities; missing policies or claims; unsupported connectors;
unknown route policies; and unauditable decisions. See the
[security model](docs/security/model.md).

## Storage and audit boundaries

AuthBoundry owns the semantics and integrity of authority state, not the
physical database. Storage is replaceable; the authority model is not. Current
code does not claim production-ready PostgreSQL or customer-system adapters.

```text
application logs != AuthBoundry audit != reporting projection
```

Audit records what the authority boundary decided and why. Business data does
not become the source of authority decisions.

## What AuthBoundry is not

AuthBoundry is not another login widget, an OAuth SDK, a user-table abstraction,
role-checking middleware, a frontend authorization library, or an application
gateway with authentication bolted on. Authentication is one input. The product
is the authority boundary.

If all you need is “sign in with Google,” AuthBoundry may be more infrastructure
than you need. That is intentional.

## The difference

```text
identity + sessions + users + tenants + roles + permissions + service accounts
         + delegation + audit = application-owned authority system

authority declaration -> AuthBoundry -> authoritative application context
```

AuthBoundry does not replace every identity provider or policy engine. It
provides the boundary in which they become one application authority model.

## AuthBoundry, AppPort and AppBoundry

AppPort describes an application protocol/contract. AppBoundry is the related
application platform/control-plane concept. AuthBoundry focuses specifically on
application authority. They are complementary; this package adds no
cross-product runtime dependency and does not claim to be an AppPort protocol.

## Production status

This release does not provide production implementations for Google OAuth,
GitHub OAuth, Microsoft, Apple, SAML, SCIM, MFA, passkeys, production key
infrastructure, PostgreSQL, Redis,
distributed sessions, a polished component library, TLS termination or
production-grade proxy features. Local identity, storage, session-id and proxy
signature mechanisms are for development.

### Supported CLI platforms

The packaged native CLI supports:

| Operating system | Architecture |
| --- | --- |
| Linux | x64, arm64 |
| macOS | x64, arm64 |

Windows native binaries are not included in this release.

## Development

```sh
cargo test --workspace
node --test clients/js/authboundry.test.js
npm run verify:package
```

Read the [documentation index](docs/README.md) and
[architecture invariants](docs/architecture.md).
