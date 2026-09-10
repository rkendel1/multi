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
authboundry attach --upstream http://127.0.0.1:9000
authboundry status
authboundry serve
```

With no attachment, `serve` exposes only authority endpoints and states clearly
that it is not protecting an application. With an attachment, startup fails
closed if the application target cannot be reached.
