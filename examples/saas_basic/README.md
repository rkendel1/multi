# Authority-bound SaaS example

This example demonstrates one AuthBoundry model in embedded and standalone
placements. Alice is an owner in tenant A with invoice capabilities and
delegates `invoice.create` to an invoice agent. The agent cannot charge billing.
Bob belongs to tenant B. Tests cover authentication, tenant isolation,
capabilities, agent identity, delegation and revocation, session invalidation,
and both placements.

```sh
cargo run -p saas_basic -- embedded
cargo run -p saas_basic -- serve
cargo test -p saas_basic
```
