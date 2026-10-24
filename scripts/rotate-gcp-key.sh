#!/usr/bin/env bash
# Create a fresh JSON key for one of the two zone-scoped service accounts,
# install it where it is used, then delete every older user-managed key.
# Also how each key is created the first time.
#
#   scripts/rotate-gcp-key.sh deployer   # -> Gitea Actions secret GCP_DNS_DEPLOYER_KEY
#   scripts/rotate-gcp-key.sh caddy      # -> apps stack config watchtower:caddyDnsKey
#
# Run every 90 days (runbook). Needs gcloud as the project owner, jq, curl;
# for `deployer` a Gitea token with write access to the repo (GITEA_TOKEN or
# prompted), for `caddy` a logged-in pulumi with PULUMI_CONFIG_PASSPHRASE.
#
# Why keys at all: Gitea Actions has no OIDC tokens to federate, and the
# Hetzner nodes have no Google identity. Each key can only write records in
# the one zone watchtower.jasonmross.dev.
#
# The key and the token never appear on a command line (`ps` shows those):
# they move through files in a 0700 temp dir that is shredded on exit.

set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 deployer|caddy" >&2; exit 1; }
case "$1" in
  deployer) SA_ID=watchtower-dns-deployer ;;
  caddy) SA_ID=watchtower-caddy-dns01 ;;
  *) echo "usage: $0 deployer|caddy" >&2; exit 1 ;;
esac

PROJECT="${GCP_PROJECT:-watchtower-observe}"
SA="${SA_ID}@${PROJECT}.iam.gserviceaccount.com"
GITEA_URL="${GITEA_URL:-https://gitea.jasonmross.dev}"
REPO="${GITEA_REPO:-JMR-dev/watchtower-observability-stack}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

work="$(mktemp -d)"
chmod 0700 "$work"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
umask 077

echo "==> Creating a new key for ${SA}"
gcloud iam service-accounts keys create "${work}/key.json" \
  --iam-account "$SA" --project "$PROJECT" --quiet
new_id="$(jq -r .private_key_id "${work}/key.json")"

delete_new() {
  gcloud iam service-accounts keys delete "$new_id" --iam-account "$SA" --project "$PROJECT" --quiet
}

if [[ "$1" == deployer ]]; then
  if [[ -z "${GITEA_TOKEN:-}" ]]; then
    read -rsp "Gitea token with write access to ${REPO}: " GITEA_TOKEN
    echo
  fi
  printf 'Authorization: token %s\n' "$GITEA_TOKEN" >"${work}/auth-header"
  unset GITEA_TOKEN
  echo "==> Storing it as GCP_DNS_DEPLOYER_KEY on ${REPO}"
  jq -n --rawfile data "${work}/key.json" '{data: $data}' >"${work}/body.json"
  status="$(curl -sS -o "${work}/response" -w '%{http_code}' -X PUT \
    -H @"${work}/auth-header" -H 'Content-Type: application/json' \
    --data @"${work}/body.json" \
    "${GITEA_URL}/api/v1/repos/${REPO}/actions/secrets/GCP_DNS_DEPLOYER_KEY")"
  if [[ "$status" != 201 && "$status" != 204 ]]; then
    echo "Gitea returned HTTP ${status}; deleting the new key so it doesn't linger" >&2
    cat "${work}/response" >&2 || true
    delete_new
    exit 1
  fi
else
  echo "==> Storing it as watchtower:caddyDnsKey in the apps stack"
  if ! (cd "${repo_root}/infra/apps" && pulumi config set --secret --stack prod watchtower:caddyDnsKey <"${work}/key.json" >/dev/null); then
    delete_new
    exit 1
  fi
  echo "    commit infra/apps/Pulumi.prod.yaml; the next deploy hands Caddy the new key"
fi

echo "==> Deleting older user-managed keys"
while read -r id; do
  [[ -z "$id" || "$id" == "$new_id" ]] && continue
  gcloud iam service-accounts keys delete "$id" --iam-account "$SA" --project "$PROJECT" --quiet
  echo "    deleted ${id}"
done < <(gcloud iam service-accounts keys list --iam-account "$SA" --project "$PROJECT" \
  --managed-by user --format='value(name.basename())')

echo "Done. Active key: ${new_id}."
