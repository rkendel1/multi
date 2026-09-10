#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/authport-package.XXXXXX")
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
node --input-type=module -e 'import { createAuthPort } from "authboundry"; if (typeof createAuthPort !== "function") process.exit(1)'
./node_modules/.bin/authport --help >/dev/null
cp "$root/examples/saas_basic/appport.auth" example.auth
./node_modules/.bin/authport inspect example.auth --json >/dev/null
./node_modules/.bin/authport fingerprint example.auth >/dev/null
mkdir types
printf '%s\n' 'import { createAuthPort } from "authboundry";' 'import { createAuthPortReact } from "authboundry/react";' 'createAuthPort(); createAuthPortReact({} as any);' > types/index.ts
npx --yes --package typescript tsc --strict --noEmit --module nodenext --moduleResolution nodenext --target es2022 types/index.ts
