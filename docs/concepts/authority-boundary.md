# The authority boundary

Authentication proves an external identity. AuthBoundry combines that input
with server-owned session, tenant, claim, policy and delegation state to derive
an application principal and authorization decision.

```text
request -> credential -> AuthBoundry -> principal -> tenant -> claims
    -> delegation -> capabilities -> decision -> application
```

An authority boundary makes derivation explicit, inspectable and fail-closed.
The application consumes the resulting context; it does not construct one.
Humans, agents and services are principals. Agent authority is attenuated by
delegation and policy, and revocation is evaluated at the boundary.
