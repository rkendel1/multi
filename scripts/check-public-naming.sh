#!/bin/sh
set -eu

if rg -n 'AuthPort|authport|_authport|authport_' \
  README.md \
  docs/README.md docs/concepts docs/deployment docs/security \
  examples/saas_basic/README.md \
  dist bin package.json; then
  echo "deprecated AuthPort identifier leaked into a public artifact" >&2
  exit 1
fi
