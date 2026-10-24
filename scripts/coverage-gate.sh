#!/usr/bin/env bash
# Fails unless a Go coverage profile covers 100.0% of statements.
#
#   scripts/coverage-gate.sh cover.out
set -euo pipefail
[[ $# -eq 1 ]] || { echo "usage: $0 <coverprofile>" >&2; exit 1; }
go tool cover -func="$1" | grep -v ' 100.0%$' || true
total="$(go tool cover -func="$1" | awk '/^total:/ {print $3}')"
if [[ "$total" != "100.0%" ]]; then
  echo "coverage ${total}, want 100.0%" >&2
  exit 1
fi
echo "coverage 100.0%"
