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
    if [ "$directory" = "." ]; then
      publish_directory=.
    else
      publish_directory="./$directory"
    fi
    npm publish "$publish_directory" --access public "$@"
  fi
}

platform=$(node -p '`${process.platform}-${process.arch}`')
runtime_package="packages/core-$platform"
if [ -x "$runtime_package/bin/authboundry" ]; then
  publish_if_missing "$runtime_package" "$@"
else
  echo "publish:packages: no built runtime package for $platform; skipping"
fi

publish_if_missing . "$@"
publish_if_missing packages/authboundry "$@"

deprecation='Moved to @authboundry/core. Install @authboundry/core for new applications.'
legacy_versions=$(npm view authboundry versions --json | node -e '
let input = "";
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", () => {
  const versions = JSON.parse(input || "[]");
  for (const version of Array.isArray(versions) ? versions : [versions]) {
    if (Number(version.split(".")[0]) < 2) console.log(version);
  }
});
')

for version in $legacy_versions; do
  current=$(npm view "authboundry@$version" deprecated 2>/dev/null || true)
  if [ "$current" = "$deprecation" ]; then
    echo "publish:packages: authboundry@$version is already deprecated; skipping"
  else
    npm deprecate "authboundry@$version" "$deprecation" "$@"
  fi
done
