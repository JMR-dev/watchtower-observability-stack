#!/usr/bin/env bash
# One-time, idempotent bootstrap of what Pulumi can't (or mustn't) own. Safe
# to re-run; every step checks before it creates, and nothing is deleted.
#
#   source scripts/env.sh && scripts/bootstrap.sh
#
# What it does, and why it isn't Pulumi:
#   1. Lists anything left in the Hetzner project from the old OpenTofu
#      deployment (servers, volumes, IPs, firewalls, keys, buckets), read-only,
#      so you can delete or keep each before the first `pulumi up`.
#   2. Creates the Pulumi state bucket <prefix>-pulumi-state: Pulumi needs it
#      before it can run. Versioned, old versions expire after 30 days, and a
#      bucket policy admits only the admin S3 key, so no in-cluster key can
#      read or rewrite state.
#   3. Creates the Cloud DNS zone watchtower.jasonmross.dev in
#      watchtower-observe and delegates it from jasonmross-dev (project
#      dns-jasonmross-dev), the way every jasonmross.dev subdomain is set up.
#      The zone is not a Pulumi resource so `pulumi destroy` can never take
#      DNS down.
#   4. Creates two service accounts with grants scoped to that one zone:
#      watchtower-deployer (the deploy: Pulumi writes the records) and
#      watchtower-caddy-dns01 (Caddy answers DNS-01). Keys are made by
#      scripts/rotate-gcp-key.sh.
#   5. Creates every secret in scripts/secret-names.txt in Secret Manager,
#      empty, with its payload replicated to europe-west3 only, and lets
#      watchtower-deployer read each one: a grant per secret, never
#      secretAccessor on the project. Values go in with scripts/secret.sh.
#
# Needs: gcloud (as the owner of both GCP projects), hcloud, aws, jq, and the
# environment scripts/env.sh exports (HCLOUD_TOKEN, AWS_ACCESS_KEY_ID /
# AWS_SECRET_ACCESS_KEY = the admin S3 key).

set -euo pipefail

# Several describe calls below hide gcloud's output, so a gcloud prompt
# would wait unseen. With prompts off it takes the default or fails instead.
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stack_file="${repo_root}/infra/cloud/Pulumi.prod.yaml"

GCP_PROJECT="${GCP_PROJECT:-watchtower-observe}"
PARENT_PROJECT="${PARENT_PROJECT:-dns-jasonmross-dev}"
PARENT_ZONE="${PARENT_ZONE:-jasonmross-dev}"
ZONE="${ZONE:-watchtower}"
DOMAIN="watchtower.jasonmross.dev"
S3_ENDPOINT="https://nbg1.your-objectstorage.com"
S3_REGION="nbg1"

PREFIX="$(sed -n 's/^  watchtower:bucketPrefix: //p' "$stack_file")"
PROJECT_ID="$(sed -n 's/^  watchtower:hetznerProjectId: "\{0,1\}\([0-9]*\)"\{0,1\}$/\1/p' "$stack_file")"
STATE_BUCKET="${PREFIX}-pulumi-state"

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

for tool in gcloud hcloud aws jq; do
  command -v "$tool" >/dev/null || die "$tool is required"
done
[[ -n "$PREFIX" ]] || die "watchtower:bucketPrefix missing from ${stack_file}"
[[ -n "$PROJECT_ID" ]] || die "set watchtower:hetznerProjectId in ${stack_file} first (Console URL: /projects/<id>/servers)"
[[ -n "${HCLOUD_TOKEN:-}" ]] || die "HCLOUD_TOKEN is not set (source scripts/env.sh)"
[[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]] || die "the admin S3 key is not set (source scripts/env.sh)"

s3() { aws --endpoint-url "$S3_ENDPOINT" --region "$S3_REGION" "$@"; }

# ---------------------------------------------------------------------------
log "1/5 Hetzner leftovers (read-only)"
# ---------------------------------------------------------------------------
for kind in server volume primary-ip floating-ip firewall ssh-key network placement-group; do
  printf -- '--- %s\n' "$kind"
  hcloud "$kind" list -o noheader || true
done
printf -- '--- buckets\n'
s3 s3 ls || true
echo "Delete anything above that the new stack doesn't own before the first 'pulumi up'."

# Bucket names are unique per location across all Hetzner customers.
for suffix in loki mimir-blocks mimir-ruler mimir-alertmanager tempo logs-archive; do
  b="${PREFIX}-${suffix}"
  if s3 s3api head-bucket --bucket "$b" >/dev/null 2>&1; then
    echo "note: ${b} already exists in this project; import it or delete it before 'pulumi up'"
  elif s3 s3api head-bucket --bucket "$b" 2>&1 | grep -q 403; then
    die "${b} belongs to someone else; change watchtower:bucketPrefix"
  fi
done

# ---------------------------------------------------------------------------
log "2/5 Pulumi state bucket s3://${STATE_BUCKET}"
# ---------------------------------------------------------------------------
if ! s3 s3api head-bucket --bucket "$STATE_BUCKET" >/dev/null 2>&1; then
  s3 s3api create-bucket --bucket "$STATE_BUCKET" >/dev/null
fi
s3 s3api put-bucket-versioning --bucket "$STATE_BUCKET" \
  --versioning-configuration Status=Enabled
s3 s3api put-bucket-lifecycle-configuration --bucket "$STATE_BUCKET" \
  --lifecycle-configuration '{"Rules":[{"ID":"old-versions","Status":"Enabled","Filter":{"Prefix":""},"NoncurrentVersionExpiration":{"NoncurrentDays":30}}]}'
policy="$(jq -n --arg b "$STATE_BUCKET" --arg p "arn:aws:iam:::user/p${PROJECT_ID}:${AWS_ACCESS_KEY_ID}" '{
  Version: "2012-10-17",
  Statement: [{
    Sid: "OnlyAdmin", Effect: "Deny", Action: "s3:*",
    Resource: ["arn:aws:s3:::\($b)", "arn:aws:s3:::\($b)/*"],
    NotPrincipal: {AWS: $p}
  }]
}')"
s3 s3api put-bucket-policy --bucket "$STATE_BUCKET" --policy "$policy"

# ---------------------------------------------------------------------------
log "3/5 Cloud DNS zone ${ZONE} (${DOMAIN}.), delegated from ${PARENT_ZONE}"
# ---------------------------------------------------------------------------
gcloud services enable dns.googleapis.com iam.googleapis.com secretmanager.googleapis.com --project "$GCP_PROJECT"

shard() { tr ';,' '\n' | sed -n 's/^ns-cloud-\([a-e]\)[0-9].*/\1/p' | sort -u; }
parent_ns="$(gcloud dns managed-zones describe "$PARENT_ZONE" --project "$PARENT_PROJECT" --format='value(nameServers)')"
parent_shard="$(shard <<<"$parent_ns")"

# A zone may not share a name-server shard with its parent: create, check,
# and recreate on a collision (dns-migration PLAN §3.3), at most three times.
for attempt in 1 2 3; do
  if ! gcloud dns managed-zones describe "$ZONE" --project "$GCP_PROJECT" >/dev/null 2>&1; then
    gcloud dns managed-zones create "$ZONE" --project "$GCP_PROJECT" \
      --dns-name "${DOMAIN}." --visibility public \
      --description "${DOMAIN}: watchtower's private ingest endpoint and VPN. Delegated from ${PARENT_ZONE} (${PARENT_PROJECT}). Created by scripts/bootstrap.sh."
  fi
  zone_ns="$(gcloud dns managed-zones describe "$ZONE" --project "$GCP_PROJECT" --format='value(nameServers)')"
  if [[ "$(shard <<<"$zone_ns")" != "$parent_shard" ]]; then
    break
  fi
  # Only a zone this script just made, still empty and undelegated, is ever
  # recreated.
  if gcloud dns record-sets describe "${DOMAIN}." --type NS --zone "$PARENT_ZONE" --project "$PARENT_PROJECT" >/dev/null 2>&1; then
    die "${ZONE} shares shard ${parent_shard} with its parent but is already delegated; resolve by hand"
  fi
  echo "zone landed on the parent's shard ${parent_shard}; recreating (attempt ${attempt})"
  gcloud dns managed-zones delete "$ZONE" --project "$GCP_PROJECT" --quiet
  [[ "$attempt" -lt 3 ]] || die "three shard collisions; stop and rethink"
done

sorted_list() { tr ';' '\n' | sed '/^$/d' | sort | paste -sd, -; }
zone_ns_sorted="$(sorted_list <<<"$zone_ns")"
delegated="$(gcloud dns record-sets describe "${DOMAIN}." --type NS --zone "$PARENT_ZONE" \
  --project "$PARENT_PROJECT" --format='value(rrdatas)' 2>/dev/null | sorted_list || true)"
if [[ -z "$delegated" ]]; then
  log "  adding NS ${DOMAIN}. -> ${zone_ns_sorted} in ${PARENT_ZONE}"
  gcloud dns record-sets create "${DOMAIN}." --type NS --ttl 300 \
    --zone "$PARENT_ZONE" --project "$PARENT_PROJECT" --rrdatas "$zone_ns_sorted"
elif [[ "$delegated" != "$zone_ns_sorted" ]]; then
  # Never overwritten automatically: a mismatch means someone else delegated
  # this name, and replacing it would hijack their zone.
  die "${PARENT_ZONE} already delegates ${DOMAIN} to ${delegated}, not ${zone_ns_sorted}; resolve by hand"
else
  log "  delegation already in place"
fi

# ---------------------------------------------------------------------------
log "4/5 Service accounts, scoped to zone ${ZONE}"
# ---------------------------------------------------------------------------
# IAM is eventually consistent and policy writes are read-modify-write;
# retry the errors that come from that, fail on anything else.
retry_iam() {
  local attempt out
  for attempt in 1 2 3 4 5 6; do
    if out="$("$@" 2>&1)"; then return 0; fi
    if grep -qiE 'does not exist|concurrent|409' <<<"$out"; then
      sleep $((attempt * 5)); continue
    fi
    printf '%s\n' "$out" >&2; return 1
  done
  printf '%s\n' "$out" >&2; return 1
}

ensure_sa() {
  local id=$1 description=$2
  local email="${id}@${GCP_PROJECT}.iam.gserviceaccount.com"
  if ! gcloud iam service-accounts describe "$email" --project "$GCP_PROJECT" >/dev/null 2>&1; then
    gcloud iam service-accounts create "$id" --project "$GCP_PROJECT" \
      --display-name "$id" --description "$description"
  fi
  retry_iam gcloud dns managed-zones add-iam-policy-binding "$ZONE" --project "$GCP_PROJECT" \
    --member "serviceAccount:${email}" --role roles/dns.admin
}

DEPLOYER="watchtower-deployer@${GCP_PROJECT}.iam.gserviceaccount.com"
ensure_sa watchtower-deployer "The deploy workflow: reads the stack's secrets and writes the records in ${DOMAIN}; key in the GCP_DEPLOYER_KEY Gitea secret"
ensure_sa watchtower-caddy-dns01 "Caddy in the edge pod answers ACME DNS-01 for ${DOMAIN}; key in the caddy-dns-key secret"
# googleclouddns finds its zone by LISTING the project's zones, a
# project-level permission no zone binding confers (gitea pkg/dns/dns.go).
# dns.reader is read-only; every write stays scoped to the zone.
retry_iam gcloud projects add-iam-policy-binding "$GCP_PROJECT" \
  --member "serviceAccount:watchtower-caddy-dns01@${GCP_PROJECT}.iam.gserviceaccount.com" \
  --role roles/dns.reader --condition None

# ---------------------------------------------------------------------------
log "5/5 Secret Manager: every secret, readable by watchtower-deployer"
# ---------------------------------------------------------------------------
mapfile -t secret_ids < <(sed -e 's/#.*//' -e 's/[[:space:]]//g' -e '/^$/d' "${repo_root}/scripts/secret-names.txt")
"${repo_root}/scripts/secret.sh" ensure "${secret_ids[@]}"
for id in "${secret_ids[@]}"; do
  retry_iam gcloud secrets add-iam-policy-binding "$id" --project "$GCP_PROJECT" \
    --member "serviceAccount:${DEPLOYER}" --role roles/secretmanager.secretAccessor
done

cat <<EOF

Done.
  State bucket : s3://${STATE_BUCKET} (admin key only)
  DNS          : zone ${ZONE} (${DOMAIN}.), delegated from ${PARENT_ZONE} in ${PARENT_PROJECT}
  Secrets      : ${#secret_ids[@]} in ${GCP_PROJECT}, each readable by ${DEPLOYER}

Next (docs/runbook.md, "First deploy"):
  1. dig +short NS ${DOMAIN}
  2. scripts/rotate-gcp-key.sh deployer    # Gitea secret GCP_DEPLOYER_KEY
     scripts/rotate-gcp-key.sh caddy       # secret caddy-dns-key
  3. scripts/secret.sh check               # every secret has a value
EOF
