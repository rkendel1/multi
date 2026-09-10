#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
platform=$(node -p '`${process.platform}-${process.arch}`')
cargo build --release --manifest-path "$root/Cargo.toml" --bin authboundry
mkdir -p "$root/native/$platform"
cp "$root/target/release/authboundry" "$root/native/$platform/authboundry"
chmod 755 "$root/native/$platform/authboundry" "$root/bin/authboundry.js"
