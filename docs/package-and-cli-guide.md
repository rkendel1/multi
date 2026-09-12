# AuthBoundry package and CLI guide

This guide covers installing `@authboundry/core`, adopting an existing
application, running the protected application boundary, using the generated
authentication experience and Studio, verifying a migration, and reversing it.

## Requirements

- Node.js 18 or newer
- An application with a supported local native binary
- The application development server must be running before it can be attached

The canonical package is `@authboundry/core`. The unscoped `authboundry`
package is a compatibility shim and should not be used for new installations.

## Supported platforms

The `authboundry` command included with `@authboundry/core` ships native
runtimes for these platforms:

| Operating system | Architecture | Node platform key |
| --- | --- | --- |
| Linux | x64 | `linux-x64` |
| Linux | arm64 | `linux-arm64` |
| macOS | x64 | `darwin-x64` |
| macOS | arm64 | `darwin-arm64` |

For local development or CI, set `AUTHBOUNDRY_CLI_PATH` to an alternate
`authboundry` binary if you need to test a runtime before it is packaged.

## Install

Install the package in the application repository:

```sh
npm install @authboundry/core
```

Equivalent package-manager commands are:

```sh
pnpm add @authboundry/core
yarn add @authboundry/core
```

Run the CLI through the locally installed package:

```sh
npx authboundry --help
```

## Recommended development workflow

### 1. Initialize the application

From the application root, run:

```sh
npx authboundry init
```

AuthBoundry detects the language, framework, package manager, entry point,
run command, routes, and existing authentication. It then previews every file
it intends to create or modify. No changes are applied until the preview is
approved.

Initialization normally creates:

- `authboundry.toml` — the authority contract
- `.authboundry/adoption.json` — attachment and route-discovery state
- `.authboundry/development.json` — local development users and secrets
- `.authboundry/integration.json` — bridge and cutover state
- `.authboundry/rollback/` — backups and a reversible change manifest
- a framework-native AuthBoundry provider or context bridge when supported

`.authboundry/development.json` contains generated `admin` and `user`
credentials. It is added to `.gitignore` and must not be committed.

Useful initialization variants:

```sh
# Preview without writing files
npx authboundry init --dry-run

# Machine-readable preview
npx authboundry init --dry-run --json

# Approve non-interactively, for a repository you have already reviewed
npx authboundry init --yes

# Initialize another directory
npx authboundry init ../my-application
```

Running `init` again upgrades missing generated configuration fields while
preserving values already chosen in `authboundry.toml`.

### 2. Start the application

Start the application's normal development server in one terminal. For
example:

```sh
npm start
# or
npm run dev
```

Record its origin. The origin must not contain a path. Valid examples include
`http://127.0.0.1:3000` and `http://127.0.0.1:5173`.

### 3. Attach and run AuthBoundry

The simplest development command is:

```sh
npx authboundry dev --upstream http://127.0.0.1:3000
```

Alternatively, save the attachment and run Studio separately:

```sh
npx authboundry attach --upstream http://127.0.0.1:3000
npx authboundry studio
```

The default endpoints are:

- Protected application: `http://127.0.0.1:8787/`
- Studio: `http://127.0.0.1:8787/_authboundry/studio`
- Generated sign-in: `http://127.0.0.1:8787/auth/login`
- Generated sign-up: `http://127.0.0.1:8787/auth/signup`
- Forgot password: `http://127.0.0.1:8787/auth/password/forgot`

Users should open the protected application on port `8787`, not the upstream
application directly. AuthBoundry owns the public boundary and forwards allowed
requests to the upstream.

To run without opening a browser:

```sh
npx authboundry studio --no-open
```

To use another listen address:

```sh
npx authboundry studio --addr 127.0.0.1:8888
```

### 4. Sign in and manage development users

The generated `admin` and `user` passwords are printed after initialization and
stored locally in `.authboundry/development.json`.

Studio displays development users and can create another local user. A user
created in Studio is immediately usable and is persisted to the local
development file. These accounts are development facilities, not a production
directory.

The generated experience follows the enabled `experience` and `ui` options in
`authboundry.toml`. Sign-up provisions a user with deployment-controlled claims;
the browser cannot choose an administrative role.

### 5. Check the boundary

```sh
npx authboundry status
npx authboundry verify
```

`status` distinguishes configuration, runtime reachability, attachment, and
active protection. `verify` checks the repository integration.

Studio's **Test Boundary** action confirms that a request crossed AuthBoundry
and reached the attached application.

## Protect routes and define authority

The main contract lives in `authboundry.toml`:

```toml
use auth {
  providers = [local]
  tenant = false
  isolation = "strict"
  agents = false

  claims = {
    role = enum["admin", "user"]
  }

  policy = {}

  experience = {
    sign_in = enabled
    sign_up = enabled
    sign_out = enabled
    password = enabled
    password_reset = enabled
    password_change = enabled
    session_management = enabled
    email_verification = disabled
    mfa = disabled
    passkeys = disabled
  }

  password = {
    min_length = 12
    max_length = 128
    history_count = 5
    allow_password_change = true
    allow_password_reset = true
  }

  storage = {
    authority = "feltdb"
    audit = "feltdb"
    reporting = "authboundry_projection"
  }

  ui = {
    mode = "generated"
    theme = "authboundry-default"
    login = "default"
    signup = "default"
    password_forgot = "default"
    password_reset = "default"
    password_change = "default"
    account = "default"
    sessions = "default"
  }
}
```

Inspect the derived contract after editing it:

```sh
npx authboundry inspect authboundry.toml
npx authboundry routes authboundry.toml
npx authboundry providers authboundry.toml
npx authboundry password-policy authboundry.toml
npx authboundry fingerprint authboundry.toml
```

Use `--json` where supported for automation.

## Password reset and email delivery

Password-reset requests cross the MailPort boundary. Configure MailPort in the
contract:

```toml
use mail
mail {
  identities {
    auth = "auth@example.com"
  }
  templates {
    password_reset = "./emails/password-reset.html"
    email_verification = "./emails/email-verification.html"
  }
}
```

Then provide the runtime connection:

```sh
export MAILPORT_URL=http://127.0.0.1:8790
export MAILPORT_API_KEY=replace-with-your-key
npx authboundry studio
```

`MAILPORT_API_KEY` is required only when the MailPort deployment requires a
bearer credential. Without a working MailPort service, the reset page exists
but no production email can be delivered.

## React client API

Initialization installs the framework bridge automatically when the project is
recognized. For a manual React integration:

```tsx
import React from "react";
import { createAuthBoundryReact } from "@authboundry/core/react";

const auth = createAuthBoundryReact(React);
export const useAuth = auth.useAuth;

root.render(
  <auth.AuthBoundry>
    <App />
  </auth.AuthBoundry>,
);
```

Inside a component:

```tsx
const state = useAuth();

if (!state.auth.authenticated) return <p>Sign in required</p>;
return <p>Signed in as {state.auth.principal?.id}</p>;
```

The React state is only a projection for rendering. It is not an authorization
boundary. The server must make every access-control decision.

## Framework-neutral browser API

```js
import { createAuthBoundry } from "@authboundry/core";

const authboundry = createAuthBoundry();
const session = await authboundry.session();

console.log(session.authenticated);
console.log(session.principal);
console.log(session.claims);
console.log(session.capabilities);

// Authoritative server check
await authboundry.authorize("invoice.create");

// Rendering hint only
if (authboundry.can("invoice.create")) {
  // Show the button; the server still decides whether the action is allowed.
}
```

## Verified migration and reversible offboarding

AuthBoundry preserves incumbent authentication during adoption. Do not remove
the existing system until runtime cutover verification succeeds.

```sh
# Verify public access, anonymous denial, sign-in, protected forwarding,
# direct-access bypass prevention, and the rollback journal
npx authboundry cutover --server http://127.0.0.1:8787 --yes

# Only after successful cutover
npx authboundry offboard-auth --yes
```

To restore the original integration files:

```sh
npx authboundry rollback --yes
```

Rollback uses the recorded manifest and backups. Review source control before
and after all cutover, offboarding, and rollback operations.

## Standalone server options

For explicit or test-oriented operation:

```sh
npx authboundry serve authboundry.toml \
  --addr 127.0.0.1:8787 \
  --tenant acme \
  --account 'alice:development-secret:role=owner@acme' \
  --grant 'invoice.read=role:owner' \
  --upstream http://127.0.0.1:3000 \
  --public /health \
  --require '/invoices=invoice.read'
```

Options:

| Option | Purpose |
| --- | --- |
| `--addr ADDRESS` | Boundary listen address |
| `--tenant NAME` | Tenant to serve; repeatable |
| `--account USER:PASS:CLAIMS` | Seed a development account |
| `--grant CAPABILITY=CLAIM:VALUE` | Map a claim to a capability |
| `--upstream URL` | Application origin behind AuthBoundry |
| `--public PATH` | Public path prefix; repeatable |
| `--require PATH=CAPABILITY` | Required capability for a path prefix |

Command-line accounts and the in-memory reference stores are intended for
development and tests.

## Contract administration commands

```sh
# Compare discovered application authority with the declaration
npx authboundry reconcile authboundry.toml
npx authboundry drift authboundry.toml --check

# Review a proposed authority declaration
npx authboundry propose authboundry.toml

# Inspect the running boundary
npx authboundry policies --server http://127.0.0.1:8787
npx authboundry policy show POLICY_ID --server http://127.0.0.1:8787
npx authboundry audit --server http://127.0.0.1:8787
npx authboundry explain DECISION_ID --server http://127.0.0.1:8787
```

Mutating authority proposals require an explicit approval/apply step:

```sh
npx authboundry propose CHANGE_TYPE --dry-run
npx authboundry propose CHANGE_TYPE
npx authboundry approve --proposal-id PROPOSAL_ID --yes
npx authboundry apply --proposal-id PROPOSAL_ID --yes
```

Use `npx authboundry --help` as the authoritative list of commands and flags for
the installed package version.

## Troubleshooting

### The protected application returns 502

Confirm the application is running and that the attachment uses its exact HTTP
origin:

```sh
npx authboundry attach --upstream http://127.0.0.1:3000 --yes
npx authboundry status
```

Do not attach `https://` to a development server that only speaks HTTP, and do
not include a trailing application path.

### The page loads but scripts or WebSockets fail

Open the application through `http://127.0.0.1:8787/`. Ensure the installed
package includes the latest proxy fixes for development-server assets and
WebSockets. Restart both the upstream server and AuthBoundry after upgrading.

### Credentials are unknown

Read the ignored local file:

```sh
npx authboundry init
```

The command prints the development credentials. They also appear in Studio and
in `.authboundry/development.json`.

### A configured feature is absent

Check both `experience` and `ui` in `authboundry.toml`. A UI selection does not
enable a disabled capability. Some declared capabilities—such as MFA and
passkeys—may be represented by the contract but remain unavailable until their
runtime provider is implemented. AuthBoundry should not be considered to
provide those flows merely because their options parse successfully.
