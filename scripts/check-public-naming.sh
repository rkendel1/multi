#!/bin/sh
set -eu

paths="README.md docs/README.md docs/concepts docs/deployment docs/security examples/saas_basic/README.md dist bin package.json"

if command -v rg >/dev/null 2>&1; then
  matches=$(rg -n 'AuthPort|authport|_authport|authport_' $paths || true)
else
  matches=$(grep -ERn 'AuthPort|authport|_authport|authport_' $paths || true)
fi

if [ -n "$matches" ]; then
  printf '%s\n' "$matches"
  echo "deprecated AuthPort identifier leaked into a public artifact" >&2
  exit 1
fi
