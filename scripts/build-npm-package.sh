#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
platform=$(node -p '`${process.platform}-${process.arch}`')
case "$platform" in
  darwin-arm64|darwin-x64|linux-arm64|linux-x64) ;;
  *)
    echo "build-npm-package: unsupported CLI platform: $platform" >&2
    echo "Supported platforms: darwin-arm64, darwin-x64, linux-arm64, linux-x64" >&2
    exit 1
    ;;
esac
cargo build --release --manifest-path "$root/Cargo.toml" --bin authboundry
mkdir -p "$root/native/$platform"
cp "$root/target/release/authboundry" "$root/native/$platform/authboundry"
if [ -d "$root/packages/core-$platform" ]; then
  mkdir -p "$root/packages/core-$platform/bin"
  cp "$root/target/release/authboundry" "$root/packages/core-$platform/bin/authboundry"
  chmod 755 "$root/packages/core-$platform/bin/authboundry"
fi
chmod 755 "$root/native/$platform/authboundry" "$root/bin/authboundry.js"
