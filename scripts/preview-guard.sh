#!/usr/bin/env bash
# Refuse a Pulumi preview that would replace or delete stateful resources,
# unless ALLOW_REPLACE=true (deploy.yml's allow_replace dispatch input).
#
#   pulumi preview --json >preview.json
#   scripts/preview-guard.sh preview.json '<type-regex>'
#
# The regex matches the type part of each step's URN, e.g.
# 'hcloud:index/server:Server|minio:index/s3Bucket:S3Bucket'.

set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 <preview.json> <type-regex>" >&2; exit 1; }
destructive="$(jq -r --arg re "$2" '
  .steps[]?
  | select(.op == "replace" or .op == "create-replacement" or .op == "delete-replaced" or .op == "delete")
  | select(.urn | split("::")[2] | test($re))
  | "\(.op)\t\(.urn)"' "$1")"

if [[ -z "$destructive" ]]; then
  echo "No destructive changes to guarded resources."
  exit 0
fi
echo "Destructive changes to guarded resources:"
echo "$destructive"
if [[ "${ALLOW_REPLACE:-false}" != "true" ]]; then
  echo "Refusing without allow_replace=true (a workflow_dispatch input). Check the runbook first:" >&2
  echo "replacing a node, a bucket or a volume can lose data or the cluster's quorum." >&2
  exit 3
fi
echo "allow_replace=true: proceeding."
