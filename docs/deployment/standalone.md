# Standalone deployment

```text
Browser -> AuthBoundry -> Existing Application
```

AuthBoundry owns the external socket, strips inbound authority headers, derives
a fresh context and denies unknown route policies. The placement changes. The
authority model does not.

Adoption begins configured but unattached. A standalone attachment requires an
explicit, reachable upstream:

```sh
authboundry attach --upstream http://localhost:9000
authboundry status
authboundry verify
authboundry serve
```

The upstream is an explicit HTTP or HTTPS origin with a port, not a route.
AuthBoundry preserves the configured hostname (`localhost`, IPv4 or bracketed
IPv6), resolves it at connection time and uses that same origin for proxying.

With no attachment, `serve` exposes only authority endpoints and states clearly
that it is not protecting an application. With an attachment, startup fails
closed if the application target cannot be reached.
