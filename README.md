# AuthPort

AuthPort turns authentication and authorization from application plumbing into a
declared capability. An application states the identity and authority it needs;
AuthPort supplies the connectors, the runtime, the durable state, the management
surfaces and the default UI.

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
or tenant lookup: those are the capability's to own.

Humans and agents are both first-class principals under one authority model.
An agent is not a user with a special role.

## The model

```
Connector                      proves an external identity
    |                          (Google, GitHub, email, local, …)
    v
ExternalIdentity               connector + subject + attributes
    |
    v                          resolved by the auth mesh, never by the connector
(tenant, connector, subject) -> exactly one Principal
    |
    v
Principal                      human | agent | service
    |
    +-- claims  --> policy --> capability
    +-- delegation --------> capability (agent, acting for a human)
```

External providers establish identity. The application owns the principal, so
one principal can hold several proven external identities (account linking) and
the same external subject in two tenants is two different principals.

### Authority for agents

```
Human  --delegates-->  Agent  --invokes-->  Capability
```

A delegation is tenant-bound, capability-scoped, time-bound, revocable and
audited, and it can never widen authority: every delegated capability must
already be held by the delegator. The runtime keeps the two principals distinct —
`principal = agent_x, delegated_by = human_y` is never collapsed into
`principal = human_y` — and every grant explains itself:

```
invoice.create
  principal: prn_655b794f817fce3f (agent)
  tenant: acme
  policy: acme-policy
  authority: delegated
  delegation: delegation-invoices
  delegated_by: prn_d41c578c5ddbb988
  basis:
    delegation:prn_d41c578c5ddbb988
```

## Inspecting a contract

The generated surface is inspectable without running the application:

```
$ authport inspect examples/saas_basic/appport.auth

AuthPort · Auth
────────────────────────

Multi-tenant: yes
Isolation: strict
Contract: e1455c6571713042
Surface: 3a2450df0f8782a5

Providers:
  ✓ local

Claims:
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
...
Generated surfaces:
  /auth/login
  /auth/signup
  /auth/logout
  /auth/session
  /auth/providers
  /auth/tenant
  /auth/tenants
  /auth/agents
  /auth/delegations
```

`authport` also has `fingerprint`, `routes`, `providers` and `inspect --json`.
Semantically identical declarations produce the same canonical contract and the
same fingerprint, so the surface can be diffed and snapshotted.

Surfaces are derived, never listed twice: `agents = false` removes the agent and
delegation surfaces, a single provider removes account linking, and the default
UI reads the same provider list the runtime authenticates against.

## Crates

| Crate | Responsibility |
| --- | --- |
| `contract` | Principals, tenants, identities, claims, delegations, ids |
| `dsl` | `use auth { ... }`, canonicalization, contract fingerprint |
| `providers` | Connector contract, catalog and registry |
| `surface` | `AuthSurface` derivation, inspection, UI contract |
| `storage` | Tenant roots, identities, principals, sessions, delegations, audit |
| `authz` | Policy evaluation and capability provenance |
| `runtime` | `AuthMesh`: authentication, resolution, sessions, delegation |
| `cli` | `authport`, the inspection surface |

## Connectors

Connectors are resolved through the registry, so adding one does not change the
authentication flow. `local` is implemented end to end and used by the tests and
the example. `google`, `github`, `microsoft`, `apple`, `email`, `magic_link`,
`password`, `sso` and `jwt` are declared in the catalog and appear in the
generated surface, but fail explicitly (`declared but not implemented`) rather
than degrading to something permissive. A provider name outside the catalog is
refused when the registry is built.

## Security posture

Everything fails closed. Unknown connector, unsupported connector, unknown
tenant, unknown principal, invalid/expired/revoked session, expired or revoked
delegation, revoked or suspended agent, wrong tenant, missing policy, missing or
undeclared claim, and ungranted capability are all denials. There is no fallback
authentication, no implicit tenant, no anonymous escalation, and no capability
inferred from provider identity alone. An authorization that cannot be audited is
not an authorization.

## Not implemented yet

Production OAuth (Google, GitHub, Microsoft, Apple), SAML, SCIM, MFA, password
reset, production email delivery, production token/key infrastructure, Postgres,
Redis, a React component library, billing and a production agent runtime. The
local connector's credential digest is a stable non-secret hash, not a password
storage scheme. These are connector, backend and UI work on top of the contract
this repository establishes.

## Running

```
cargo test --workspace
cargo run -p saas_basic
cargo run -p appport-auth-mesh-cli -- inspect examples/saas_basic/appport.auth
```

`examples/saas_basic` shows the whole model: Alice (human, tenant A) delegating
invoice creation to an invoice agent, Bob isolated in tenant B, and revocation
removing the agent's authority while leaving Alice's intact.
