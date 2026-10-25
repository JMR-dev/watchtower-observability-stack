#!/usr/bin/env bash
# One-time, idempotent bootstrap of what Pulumi can't (or mustn't) own. Safe
# to re-run; every step checks before it creates, and nothing is deleted.
#
#   source scripts/env.sh && scripts/bootstrap.sh
#
# What it does, and why it isn't Pulumi:
#   1. Lists anything left in the Hetzner project (servers, volumes, IPs,
#      firewalls, keys, buckets), read-only, so you can delete or keep each
#      before the first `pulumi up`.
#   2. Creates the Pulumi state bucket <prefix>-pulumi-state: Pulumi needs it
#      before it can run. Versioned, old versions expire after 30 days, and a
#      bucket policy admits only the admin S3 key, so the cluster key the
#      servers hold can never read or rewrite state.
#   3. Creates the Cloud DNS zone watchtower.jasonmross.dev in
#      watchtower-observe and delegates it from jasonmross-dev (project
#      dns-jasonmross-dev), the way every jasonmross.dev subdomain is set up.
#      The zone is not a Pulumi resource so `pulumi destroy` can never take
#      DNS down.
#   4. Creates two service accounts with grants scoped to that one zone:
#      watchtower-deployer (the deploy: Pulumi writes the records) and
#      watchtower-caddy-dns01 (Caddy answers DNS-01).
#   5. Creates the Artifact Registry repo `watchtower` (europe-west3, docker,
#      immutable tags, keeps the 10 newest versions of each image) for the
#      caddy and patroni images, plus two service accounts scoped to that one
#      repo: watchtower-image-pusher (CI writes) and watchtower-image-puller
#      (the hosts read).
#   6. Creates every secret the deploy workflow reads (`secret.sh
#      deploy-ids`) in Secret Manager, empty, with its payload replicated to
#      europe-west3 only, and lets watchtower-deployer read each: a grant per
#      secret, never secretAccessor on the project. Owner-only secrets such
#      as gar-push-key are never read by the deploy, so never granted.
#      Values go in with scripts/secret.sh. The secrets the deploy writes
#      (deploy_written; wireguard-owner-peer, the owner's first VPN peer) it
#      may add versions to and never read: secretVersionAdder alone.
#
# Keys are made by scripts/rotate-gcp-key.sh.
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
S3_ENDPOINT="https://fsn1.your-objectstorage.com"
S3_REGION="fsn1"
GAR_LOCATION="${GAR_LOCATION:-europe-west3}"
GAR_REPO="${GAR_REPO:-watchtower}"

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
log "1/6 Hetzner leftovers (read-only)"
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
log "2/6 Pulumi state bucket s3://${STATE_BUCKET}"
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
log "3/6 Cloud DNS zone ${ZONE} (${DOMAIN}.), delegated from ${PARENT_ZONE}"
# ---------------------------------------------------------------------------
gcloud services enable dns.googleapis.com iam.googleapis.com secretmanager.googleapis.com \
  artifactregistry.googleapis.com --project "$GCP_PROJECT"

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
log "4/6 Service accounts, scoped to zone ${ZONE}"
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

sa_email() { printf '%s@%s.iam.gserviceaccount.com' "$1" "$GCP_PROJECT"; }

ensure_sa() {
  local id=$1 description=$2
  if ! gcloud iam service-accounts describe "$(sa_email "$id")" --project "$GCP_PROJECT" >/dev/null 2>&1; then
    gcloud iam service-accounts create "$id" --project "$GCP_PROJECT" \
      --display-name "$id" --description "$description"
  fi
}

# gcloud has no add-iam-policy-binding for managed zones, so read, add and
# write back; set-iam-policy sends the etag it read, so a concurrent change
# fails and retry_iam starts over.
zone_bind() {
  local member=$1 role=$2 policy file
  policy="$(gcloud dns managed-zones get-iam-policy "$ZONE" --project "$GCP_PROJECT" --format json)" || return 1
  if jq -e --arg m "$member" --arg r "$role" \
    'any(.bindings[]?; .role == $r and any(.members[]; . == $m))' <<<"$policy" >/dev/null; then
    return 0
  fi
  file="$(mktemp)"
  jq --arg m "$member" --arg r "$role" '
    .bindings = ((.bindings // []) as $b
      | if any($b[]; .role == $r)
        then $b | map(if .role == $r then .members = (.members + [$m] | unique) else . end)
        else $b + [{role: $r, members: [$m]}] end)' <<<"$policy" >"$file"
  gcloud dns managed-zones set-iam-policy "$ZONE" --project "$GCP_PROJECT" --policy-file "$file" >/dev/null \
    || { rm -f "$file"; return 1; }
  rm -f "$file"
}

zone_admin() {
  retry_iam zone_bind "serviceAccount:$(sa_email "$1")" roles/dns.admin
}

DEPLOYER="$(sa_email watchtower-deployer)"
ensure_sa watchtower-deployer "The deploy workflow: reads the stack's secrets and writes the records in ${DOMAIN}; key in the GCP_DEPLOYER_KEY Gitea secret"
zone_admin watchtower-deployer
ensure_sa watchtower-caddy-dns01 "Caddy on the proxy answers ACME DNS-01 for ${DOMAIN}; key in the caddy-dns-key secret"
zone_admin watchtower-caddy-dns01
# googleclouddns finds its zone by LISTING the project's zones, a
# project-level permission no zone binding confers (gitea pkg/dns/dns.go).
# dns.reader is read-only; every write stays scoped to the zone.
retry_iam gcloud projects add-iam-policy-binding "$GCP_PROJECT" \
  --member "serviceAccount:watchtower-caddy-dns01@${GCP_PROJECT}.iam.gserviceaccount.com" \
  --role roles/dns.reader --condition None

# ---------------------------------------------------------------------------
log "5/6 Artifact Registry ${GAR_LOCATION}-docker.pkg.dev/${GCP_PROJECT}/${GAR_REPO}"
# ---------------------------------------------------------------------------
if ! gcloud artifacts repositories describe "$GAR_REPO" --location "$GAR_LOCATION" --project "$GCP_PROJECT" >/dev/null 2>&1; then
  # Tags are commit SHAs and the deploy reuses an existing one, so a tag must
  # never move.
  gcloud artifacts repositories create "$GAR_REPO" --project "$GCP_PROJECT" \
    --location "$GAR_LOCATION" --repository-format docker --immutable-tags \
    --labels app=watchtower \
    --description "watchtower's own images (caddy, patroni). Created by scripts/bootstrap.sh."
fi
# Storage is billed: keep each image's 10 newest versions, delete the rest
# once they are a week old.
cleanup="$(mktemp)"
trap 'rm -f "$cleanup"' EXIT
cat >"$cleanup" <<'JSON'
[
  {"name": "keep-newest", "action": {"type": "Keep"}, "mostRecentVersions": {"keepCount": 10}},
  {"name": "delete-old", "action": {"type": "Delete"}, "condition": {"tagState": "any", "olderThan": "7d"}}
]
JSON
gcloud artifacts repositories set-cleanup-policies "$GAR_REPO" --project "$GCP_PROJECT" \
  --location "$GAR_LOCATION" --policy "$cleanup" --no-dry-run >/dev/null

repo_role() {
  retry_iam gcloud artifacts repositories add-iam-policy-binding "$GAR_REPO" --project "$GCP_PROJECT" \
    --location "$GAR_LOCATION" --member "serviceAccount:$(sa_email "$1")" --role "$2"
}
ensure_sa watchtower-image-pusher "CI pushes the caddy and patroni images to ${GAR_REPO}; key in gar-push-key, copied to the GAR_PUSH_KEY Gitea secret"
repo_role watchtower-image-pusher roles/artifactregistry.writer
ensure_sa watchtower-image-puller "The hosts pull watchtower's images from ${GAR_REPO}; key in gar-pull-key"
repo_role watchtower-image-puller roles/artifactregistry.reader

# ---------------------------------------------------------------------------
log "6/6 Secret Manager: every secret the deploy reads, readable by watchtower-deployer"
# ---------------------------------------------------------------------------
mapfile -t secret_ids < <("${repo_root}/scripts/secret.sh" deploy-ids)
[[ "${#secret_ids[@]}" -gt 0 ]] || die "deploy.yml reads no secrets; is the setup action's secrets: block intact?"
"${repo_root}/scripts/secret.sh" ensure "${secret_ids[@]}"
granted=0
for id in "${secret_ids[@]}"; do
  # deploy.yml never reads the push key (a Go test keeps it so): the image
  # job gets it as its own Actions secret, and a leaked deployer key must
  # not be able to push images too. Checked here as well.
  [[ "$id" == gar-push-key ]] && continue
  retry_iam gcloud secrets add-iam-policy-binding "$id" --project "$GCP_PROJECT" \
    --member "serviceAccount:${DEPLOYER}" --role roles/secretmanager.secretAccessor
  granted=$((granted + 1))
done

# Written by the deploy, read only by the owner (`secret.sh pull`). A Go test
# keeps this list equal to names.DeployWrittenSecrets.
deploy_written=(wireguard-owner-peer)
"${repo_root}/scripts/secret.sh" ensure "${deploy_written[@]}"
for id in "${deploy_written[@]}"; do
  gcloud secrets update "$id" --project "$GCP_PROJECT" --update-labels writer=deploy >/dev/null
  retry_iam gcloud secrets add-iam-policy-binding "$id" --project "$GCP_PROJECT" \
    --member "serviceAccount:${DEPLOYER}" --role roles/secretmanager.secretVersionAdder
done

cat <<EOF

Done.
  State bucket : s3://${STATE_BUCKET} (admin key only)
  DNS          : zone ${ZONE} (${DOMAIN}.), delegated from ${PARENT_ZONE} in ${PARENT_PROJECT}
  Registry     : ${GAR_LOCATION}-docker.pkg.dev/${GCP_PROJECT}/${GAR_REPO}
  Secrets      : the ${#secret_ids[@]} the deploy reads, in ${GCP_PROJECT}; ${granted} readable by ${DEPLOYER},
                 which may only add to ${deploy_written[*]}

Next (docs/runbook.md, "First deploy"):
  1. dig +short NS ${DOMAIN}
  2. scripts/rotate-gcp-key.sh deployer    # Gitea secret GCP_DEPLOYER_KEY
     scripts/rotate-gcp-key.sh caddy       # secret caddy-dns-key
     scripts/rotate-gcp-key.sh pusher      # secret gar-push-key + Gitea GAR_PUSH_KEY
     scripts/rotate-gcp-key.sh puller      # secret gar-pull-key
  3. scripts/secret.sh check               # every secret has a value
EOF
