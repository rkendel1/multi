#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

npm run verify:package

publish_if_missing() {
  directory=$1
  shift
  name=$(node -p "require('./$directory/package.json').name")
  version=$(node -p "require('./$directory/package.json').version")
  if npm view "$name@$version" version >/dev/null 2>&1; then
    echo "publish:packages: $name@$version is already published; skipping"
  else
    npm publish "$directory" --access public "$@"
  fi
}

publish_if_missing . "$@"
publish_if_missing packages/authboundry "$@"
npm deprecate 'authboundry@<2.0.0' 'Moved to @authboundry/core. Install @authboundry/core for new applications.' "$@"
