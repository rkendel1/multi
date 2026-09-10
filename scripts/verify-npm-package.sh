#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/authboundry-package.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
export npm_config_cache="$work/npm-cache"
cd "$root"
npm run build
npm test
npm pack --dry-run
tarball=$(npm pack --pack-destination "$work" | tail -n 1)
cd "$work"
npm init -y >/dev/null
npm install "./$tarball" >/dev/null
node --input-type=module -e 'import { createAuthBoundry } from "@authboundry/core"; if (typeof createAuthBoundry !== "function") process.exit(1)'
./node_modules/.bin/authboundry --help >/dev/null
./node_modules/.bin/authboundry status >/dev/null
cp "$root/examples/saas_basic/appport.auth" example.auth
./node_modules/.bin/authboundry inspect example.auth --json >/dev/null
./node_modules/.bin/authboundry fingerprint example.auth >/dev/null
mkdir types
printf '%s\n' 'import { createAuthBoundry } from "@authboundry/core";' 'import { createAuthBoundryReact } from "@authboundry/core/react";' 'createAuthBoundry(); createAuthBoundryReact({} as any);' > types/index.ts
npx --yes --package typescript tsc --strict --noEmit --module nodenext --moduleResolution nodenext --target es2022 types/index.ts
npx --yes --package typescript@4.9.5 tsc --strict --noEmit --module commonjs --moduleResolution node --target es2017 types/index.ts

# Verify the unscoped redirect against the already-installed local core.
shim_tarball=$(npm pack "$root/packages/authboundry" --pack-destination "$work" | tail -n 1)
npm install --offline "./$shim_tarball" >/dev/null
node --input-type=module -e 'import { createAuthBoundry } from "authboundry"; if (typeof createAuthBoundry !== "function") process.exit(1)'
./node_modules/.bin/authboundry --help >/dev/null
