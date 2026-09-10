# Embedded deployment

```text
Application Server -> AuthBoundry -> Application Handler
```

The application owns its server and invokes the authority runtime before a
handler. AuthBoundry derives and authorizes the context. An `AuthContext` is
created only by this boundary.
