# Standalone deployment

```text
Browser -> AuthBoundry -> Existing Application
```

AuthBoundry owns the external socket, strips inbound authority headers, derives
a fresh context and denies unknown route policies. The placement changes. The
authority model does not.
