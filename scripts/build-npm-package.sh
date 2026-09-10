#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
platform=$(node -p '`${process.platform}-${process.arch}`')
cargo build --release --manifest-path "$root/Cargo.toml" --bin authport
mkdir -p "$root/native/$platform"
cp "$root/target/release/authport" "$root/native/$platform/authport"
chmod 755 "$root/native/$platform/authport" "$root/bin/authport.js"
