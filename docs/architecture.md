# AuthPort architecture invariants

These are the properties the system is built to hold. Each one names the tests
that would fail if it stopped being true.

## One authority model

Embedded and standalone are two placements of the same runtime. The mode is a
tag on `AuthPortRuntime`; it selects no code path in authentication, session
resolution, policy evaluation or delegation.

```
AuthConfig -> AuthMesh -> AuthPortRuntime -> AuthBoundary -> AuthContext
                                |
                    +-----------+-----------+
                    |                       |
              Embedded                 Standalone
   bound to the application server   owns the server, app behind it
```

- `crates/boundary/tests/authority.rs::embedded_and_standalone_decide_identically`
  — same contract, same surface, same decisions, and a session opened in one
  placement is honoured by the other.
- `examples/saas_basic/tests/backend_boundary.rs::embedded_and_standalone_agree`
  — a twenty-step scenario over HTTP produces byte-identical results in both.

## Server authority

Client state is never authoritative. A request contributes a credential; the
principal, tenant, claims, capabilities and delegation are read back from
AuthPort's own state.

- `AuthContext` has a private field and no public constructor: outside the
  boundary crate it cannot be built, only received.
- Inbound `x-authport-*` headers are stripped before a request is examined
  (`BoundaryRequest::sanitized`), so a client cannot inject the context a
  standalone deployment forwards upstream.
- A tenant named by the caller is only ever checked against the tenant the
  session belongs to.
- `a_client_cannot_manufacture_backend_authority`,
  `the_client_says_yes_and_the_server_says_no`,
  `the_proxy_strips_client_supplied_context`,
  `reserved_headers_never_reach_the_boundary`.

## One configuration

The same `AuthConfig` drives the runtime, the routes, the providers, the UI,
inspection and the fingerprint. There is no second provider list.

- Routes come from `AuthSurface::derive`; the server mounts what the surface
  says and nothing else.
- The generated sign-in page reads `AuthSurface`'s provider list, so a
  declared-but-unimplemented connector is named honestly and never offered as a
  usable button.
- `the_generated_ui_offers_only_connectors_that_work`,
  `the_session_cookie_is_the_one_the_contract_names`,
  `renders_json_routes_providers_and_fingerprints`.

## One identity model

Connectors prove external identity. AuthPort owns application principals, and
`(tenant, connector, external_subject)` resolves to exactly one of them.

- `crates/runtime/tests/end_to_end_auth.rs::external_identities_resolve_deterministically_and_uniquely`.

## One authorization model

Humans, agents and services are answered by the same policy engine, and a grant
retains its provenance.

- `agents_act_within_their_delegation` — the agent's grant names the agent as
  the principal and Alice as the delegator; the two are never collapsed.
- `capabilities_gate_the_application` — the tenant's owner still cannot charge.

## One boundary

The application implements no authentication, session validation, tenant
resolution, claims resolution, authorization or delegation of its own.

`examples/saas_basic` contains exactly one file of auth wiring (`bootstrap.rs`:
the declaration, the account directory, the policy, the tenants). Handlers
receive a context they did not assemble. In standalone mode the upstream
application's only security rule is "refuse anything AuthPort did not vouch
for".

## Fail closed

Every one of these is a denial with a named reason, never a fallback:

| Condition | Reason |
| --- | --- |
| no credential | `missing_credential` |
| malformed or unknown session | `invalid_session` |
| expired session | `expired_session` |
| revoked session | `revoked_session` |
| unknown tenant | `unknown_tenant` |
| session addressed at another tenant | `tenant_mismatch` |
| unknown principal | `unknown_principal` |
| suspended or revoked agent | `agent_suspended`, `agent_revoked` |
| expired or revoked delegation | `expired_delegation`, `revoked_delegation` |
| capability not granted | `capability_not_granted` |
| no policy for the tenant | `policy_not_found` |
| missing or undeclared claim | `missing_claim`, `claim_mismatch` |
| unsupported or undeclared connector | `unsupported_connector` |
| path not covered by a route policy | `no_route_policy` |
| the decision cannot be audited | `audit_unavailable` |

An unlisted path is refused rather than forwarded, and a public route resolves a
credential opportunistically but never makes an authorization decision from one.

## Audit

An authorization that cannot be durably recorded is not an authorization: the
audit write happens inside `AuthMesh::authorize`, and a failed write denies.
There is no second audit implementation in the HTTP layer.

- `examples/saas_basic/tests/backend_boundary.rs::an_unrecordable_decision_is_denied`.

Audit events use the canonical `authport.audit/v1` shape: id, timestamp, tenant,
principal, delegator, session, delegation, run, action, resource, decision,
reason, authority revision, contract fingerprint, durability and metadata.
Storage implementations append events; they do not update or delete audit rows
as normal authority operations. `AuditStore` is the durable historical security
record. `AuditSink` is an optional external integration and is never treated as
authoritative merely because it receives a copy.

- `crates/storage/tests/storage_conformance.rs::audit_store_is_append_ordered_tenant_scoped_and_exportable`.

## Storage boundary

The domain model depends on storage capabilities, not database brands. The
storage contract is split by authority semantics: identity, tenant, session,
credential, policy, delegation, agent, run, audit and reporting. `MeshStores`
aggregates those capabilities but does not require that they all come from one
backend. A deployment can therefore use FeltDB for authority, an enterprise
audit store for historical evidence and a warehouse for reporting projections
without changing the application authorization model.

FeltDB is the easy default path and has a first-class topology descriptor with
durable commit, transactions, conditional writes, indexes, history, export/import
and append-only audit. The PostgreSQL reference topology satisfies the same
semantic conformance checks to show the authority model survives a different
storage architecture.

- `crates/storage/tests/storage_conformance.rs::felt_db_and_postgres_reference_topologies_satisfy_authority_semantics`.

Reporting is derived from canonical audit events. Reporting stores and external
sinks are explicitly non-authoritative; they may support analytics and export,
but current authority still comes from the authority store and historical
security evidence still comes from the audit store.

## Development-only mechanisms

Called out so they are not mistaken for production posture:

- The local connector stores a stable non-secret digest, not a password hash.
- Session ids come from a per-process random seed rather than a CSPRNG.
- The standalone proxy signs the injected context with a keyed FNV digest, which
  is enough to keep an upstream on a trusted network from accepting forged
  context, and is not a MAC.
- All state is in memory.
