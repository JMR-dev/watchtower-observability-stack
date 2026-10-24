#!/usr/bin/env bash
# GDPR right to erasure (Art. 17) for logs: submit a Loki delete request for
# every line of one tenant that matches a selector, and keep a record of it.
# Ported from the old ansible playbooks/gdpr-purge.yml. Run from a WireGuard
# peer: Loki is only reachable through the tunnel.
#
#   scripts/gdpr-purge.sh <tenant> '<selector>' <start> [end]
#   scripts/gdpr-purge.sh team-alpha '{user_id="abc-123"}' 2026-01-01T00:00:00Z
#
# Loki's compactor carries out the delete after retention_delete_delay (2h).
# The record goes to the log archive under gdpr-audit/, which never expires
# and which the log shipper's key cannot overwrite; writing it needs the
# admin S3 key (source scripts/env.sh). Mimir and Tempo have no per-record
# delete: their 90- and 30-day retention is the erasure window.

set -euo pipefail

[[ $# -ge 3 ]] || { echo "usage: $0 <tenant> '<selector>' <start> [end]" >&2; exit 1; }
tenant="$1" selector="$2" start="$3" end="${4:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
LOKI="${LOKI_URL:-https://watchtower.jasonmross.dev:3100}"
S3_ENDPOINT="https://nbg1.your-objectstorage.com"
prefix="$(sed -n 's/^  watchtower:bucketPrefix: //p' "$(dirname "${BASH_SOURCE[0]}")/../infra/cloud/Pulumi.prod.yaml")"

echo "==> Delete request: tenant=${tenant} selector=${selector} ${start} .. ${end}"
status="$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "X-Scope-OrgID: ${tenant}" \
  --data-urlencode "query=${selector}" --data-urlencode "start=${start}" --data-urlencode "end=${end}" \
  "${LOKI}/loki/api/v1/delete")"
[[ "$status" == 204 ]] || { echo "Loki returned HTTP ${status}" >&2; exit 1; }

record="$(jq -n --arg t "$tenant" --arg s "$selector" --arg a "$start" --arg b "$end" \
  --arg by "$(git config user.email 2>/dev/null || whoami)" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{submitted_at: $at, submitted_by: $by, tenant: $t, selector: $s, start: $a, end: $b, status: "submitted"}')"
key="gdpr-audit/$(date -u +%Y/%m/%d)/$(date -u +%H%M%S)-${tenant}.json"
aws --endpoint-url "$S3_ENDPOINT" --region nbg1 s3 cp - "s3://${prefix}-logs-archive/${key}" <<<"$record"

echo "==> Recorded at s3://${prefix}-logs-archive/${key}"
echo "Check progress: curl -H 'X-Scope-OrgID: ${tenant}' ${LOKI}/loki/api/v1/delete"
