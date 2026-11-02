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
#      watchtower-caddy-dns01 (Caddy answers DNS-01). Also
#      watchtower-gcp-reader, with no role here and no key: gitea's own
#      stacks let it pull Gitea CI's logs and metrics. And
#      watchtower-bastion, the bastion's own identity, with no key: it may
#      read the bastion's agent peer and its Healthchecks.io ping URL (step 6)
#      and nothing else.
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
#      (deploy_written: wireguard-owner-peer, the owner's first VPN peer, and
#      wireguard-deploy-peer, its own) it may add versions to:
#      secretVersionAdder. Of those it reads back only its own peer
#      (deploy_read_back), never the owner's. The rest are the agent peers
#      of the services that ship telemetry here (docs/client-telemetry.md):
#      each one's config is readable by one identity of that service, in
#      its own project (agent_readers), and by nothing else. The bastion's
#      ping URL (bastion_readable) is made here too, empty, for
#      scripts/healthchecks.sh to fill; the bastion alone may read it.
#   7. Creates the break-glass bastion watchtower-bastion: an e2-micro in
#      us-east1 (the free tier) on a network of its own, with no external
#      address, reachable only through IAP TCP forwarding (SSH from
#      35.235.240.0/20, nothing else) and OS Login. Its traffic leaves
#      through Cloud NAT on one reserved address, which the proxy's
#      firewalls admit for SSH (breakGlassCidrs): the way in when the VPN is
#      down, and the deploy's when the proxy is rebuilt (ssh_via=bastion).
#      watchtower-deployer may log in to that one VM and tunnel to its port
#      22, nothing more. Not Pulumi: the deploy must not hold compute admin,
#      and break glass must not depend on the deploy.
#      It also ships its journal and metrics to watchtower as an agent peer
#      (docs/client-telemetry.md): its startup script (config/bastion/)
#      reads its peer with the VM's token, as watchtower-bastion, and keeps
#      every other user from the metadata server. OS Login lets a user onto
#      a VM that runs as a service account only if they may act as it, so
#      watchtower-deployer gets roles/iam.serviceAccountUser on it.
#      An existing bastion is updated in place, keeping its boot disk and
#      with it its SSH host key; anyone on it then is cut off. A new guard
#      ruleset goes on under a 10-minute rollback (config/bastion/ruleset.sh):
#      this dispatches bastion-confirm.yml, for the branch it's run from, to
#      log in as the deployer and cancel it, and waits to see which came of
#      it, in a guest attribute only root can write once the guard is on, and
#      never prints "Done" unless this boot has confirmed it. Rolled back, it
#      stops, and a rerun tries again: a fixed file has a new sha256, and the
#      same file is asked for again. The account goes on only after that ruleset
#      is confirmed, and it's asked again of the boot with the account: two
#      restarts the first time. sshd runs only with the guard loaded or on a VM
#      with no account, a user may leave nothing behind to run without logging
#      in (no crontab, no lingering), and a file that won't load falls back to a
#      guard built into the tool, so nothing of a user's runs with a token and no
#      guard unless nft itself loads nothing, when sshd stays down.
#      Writes the NAT address and the bastion's SSH host key into
#      infra/cloud/Pulumi.prod.yaml (breakGlassCidrs, bastionHostKey), never
#      to the terminal; commit the change and deploy.
#
# Keys are made by scripts/rotate-gcp-key.sh.
#
# Costs: the bastion is free-tier; Cloud NAT and its address about $4-5 a
# month.
#
# Needs: gcloud (as the owner of both GCP projects), hcloud, aws, jq, gopass and
# curl (the Gitea token, for bastion-confirm.yml), and the environment
# scripts/env.sh exports (HCLOUD_TOKEN, AWS_ACCESS_KEY_ID /
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
# The bastion. The free tier's e2-micro exists only in us-west1, us-central1
# and us-east1. Its address is fixed: the deployer's IAP grant names it.
BASTION="watchtower-bastion"
BASTION_REGION="us-east1"
BASTION_ZONE="us-east1-b"
BASTION_RANGE="10.90.0.0/28"
BASTION_IP="10.90.0.2"
IAP_RANGE="35.235.240.0/20"
GITEA_API="https://gitea.jasonmross.dev/api/v1/repos/JMR-dev/watchtower-observability-stack"

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
log "1/7 Hetzner leftovers (read-only)"
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
log "2/7 Pulumi state bucket s3://${STATE_BUCKET}"
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
log "3/7 Cloud DNS zone ${ZONE} (${DOMAIN}.), delegated from ${PARENT_ZONE}"
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
log "4/7 Service accounts, scoped to zone ${ZONE}"
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
ensure_sa watchtower-gcp-reader "Watchtower pulls Gitea CI's logs and metrics as this (Pub/Sub, Cloud Monitoring); granted in gitea's stacks, no role here"
ensure_sa watchtower-bastion "The break-glass bastion runs as this: it reads its own agent peer, wireguard-bastion-peer, and its Healthchecks.io ping URL, healthchecks-bastion-url; no key"
# googleclouddns finds its zone by LISTING the project's zones, a
# project-level permission no zone binding confers (gitea pkg/dns/dns.go).
# dns.reader is read-only; every write stays scoped to the zone.
retry_iam gcloud projects add-iam-policy-binding "$GCP_PROJECT" \
  --member "serviceAccount:watchtower-caddy-dns01@${GCP_PROJECT}.iam.gserviceaccount.com" \
  --role roles/dns.reader --condition None

# ---------------------------------------------------------------------------
log "5/7 Artifact Registry ${GAR_LOCATION}-docker.pkg.dev/${GCP_PROJECT}/${GAR_REPO}"
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
log "6/7 Secret Manager: every secret the deploy reads, readable by watchtower-deployer"
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

# Written by the deploy, read only by the owner (`secret.sh pull`) or an
# agent peer's reader. A Go test keeps this list equal to
# names.DeployWrittenSecrets.
deploy_written=(wireguard-owner-peer wireguard-deploy-peer wireguard-bastion-peer wireguard-gitea-vm-peer wireguard-vaultwarden-production-peer wireguard-vaultwarden-disposable-peer wireguard-silverbullet-vm-peer wireguard-blog-vm-peer)
"${repo_root}/scripts/secret.sh" ensure "${deploy_written[@]}"
for id in "${deploy_written[@]}"; do
  gcloud secrets update "$id" --project "$GCP_PROJECT" --update-labels writer=deploy >/dev/null
  retry_iam gcloud secrets add-iam-policy-binding "$id" --project "$GCP_PROJECT" \
    --member "serviceAccount:${DEPLOYER}" --role roles/secretmanager.secretVersionAdder
done
# Of those, the deploy reads back its own VPN peer: its way in. A Go test
# keeps this list equal to names.DeployReadBackSecrets.
deploy_read_back=(wireguard-deploy-peer)
for id in "${deploy_read_back[@]}"; do
  retry_iam gcloud secrets add-iam-policy-binding "$id" --project "$GCP_PROJECT" \
    --member "serviceAccount:${DEPLOYER}" --role roles/secretmanager.secretAccessor
done
# Each agent peer's config is read by one identity of the service it is for,
# in that service's project: a grant on that one secret. The bastion's is
# its own account here (step 4). A Go test keeps this list equal to
# names.AgentPeers.
agent_readers=(
  wireguard-bastion-peer=watchtower-bastion@watchtower-observe.iam.gserviceaccount.com
  wireguard-gitea-vm-peer=gitea-vm@gitea-496920.iam.gserviceaccount.com
  wireguard-vaultwarden-production-peer=vaultwarden-deployer@vaultwarden-497422.iam.gserviceaccount.com
  wireguard-vaultwarden-disposable-peer=vaultwarden-deployer@vaultwarden-497422.iam.gserviceaccount.com
  wireguard-silverbullet-vm-peer=cb-infra@silver-bullet-dev.iam.gserviceaccount.com
  wireguard-blog-vm-peer=blog-vm@dev-blog-494815.iam.gserviceaccount.com
)
for pair in "${agent_readers[@]}"; do
  retry_iam gcloud secrets add-iam-policy-binding "${pair%%=*}" --project "$GCP_PROJECT" \
    --member "serviceAccount:${pair#*=}" --role roles/secretmanager.secretAccessor
done
# What the bastion reads besides its peer: its Healthchecks.io ping URL, which
# scripts/healthchecks.sh stores. It may read that one secret, and the deployer
# may not. A Go test keeps this list equal to names.BastionSecrets.
bastion_readable=(healthchecks-bastion-url)
"${repo_root}/scripts/secret.sh" ensure "${bastion_readable[@]}"
for id in "${bastion_readable[@]}"; do
  retry_iam gcloud secrets add-iam-policy-binding "$id" --project "$GCP_PROJECT" \
    --member "serviceAccount:$(sa_email watchtower-bastion)" --role roles/secretmanager.secretAccessor
done

# ---------------------------------------------------------------------------
log "7/7 Break-glass bastion ${BASTION} (${BASTION_ZONE}), through IAP only"
# ---------------------------------------------------------------------------
gcloud services enable compute.googleapis.com iap.googleapis.com oslogin.googleapis.com \
  --project "$GCP_PROJECT" --quiet
compute() { gcloud compute "$@" --project "$GCP_PROJECT"; }
exists() { compute "$@" >/dev/null 2>&1; } # a describe that succeeds

# A network of its own; a custom VPC denies all ingress until a rule allows it.
exists networks describe "$BASTION" || compute networks create "$BASTION" --subnet-mode custom
exists networks subnets describe "$BASTION" --region "$BASTION_REGION" ||
  compute networks subnets create "$BASTION" --network "$BASTION" --region "$BASTION_REGION" --range "$BASTION_RANGE"
exists firewall-rules describe "${BASTION}-iap-ssh" ||
  compute firewall-rules create "${BASTION}-iap-ssh" --network "$BASTION" --direction INGRESS \
    --allow tcp:22 --source-ranges "$IAP_RANGE" --target-tags "$BASTION" \
    --description "SSH from IAP TCP forwarding, and from nowhere else"

# Out through one reserved address: the one the proxy admits.
exists addresses describe "${BASTION}-nat" --region "$BASTION_REGION" ||
  compute addresses create "${BASTION}-nat" --region "$BASTION_REGION" \
    --description "Cloud NAT for ${BASTION}; the proxy admits SSH from it (breakGlassCidrs)"
exists routers describe "$BASTION" --region "$BASTION_REGION" ||
  compute routers create "$BASTION" --network "$BASTION" --region "$BASTION_REGION"
exists routers nats describe "$BASTION" --router "$BASTION" --region "$BASTION_REGION" ||
  compute routers nats create "$BASTION" --router "$BASTION" --region "$BASTION_REGION" \
    --nat-external-ip-pool "${BASTION}-nat" --nat-all-subnet-ip-ranges

# What it runs (config/bastion/startup.sh): the metadata guard, under its
# rollback (ruleset.sh); security updates every day, rebooting at 04:00 UTC
# when one needs it; a ping of its Healthchecks.io check, at boot and daily; its
# agent peer and Alloy. The other three files it reads from its metadata at boot.
bastion_dir="${repo_root}/config/bastion"
bastion_alloy="${repo_root}/config/alloy/bastion.alloy"
bastion_files="startup-script=${bastion_dir}/startup.sh,watchtower-nftables=${bastion_dir}/nftables.conf,watchtower-ruleset=${bastion_dir}/ruleset.sh,watchtower-alloy=${bastion_alloy}"
ruleset_sha="$(sha256sum "${bastion_dir}/nftables.conf" | cut -d' ' -f1)"
BASTION_SA="$(sa_email "$BASTION")"
# OS Login lets a user onto a VM that runs as a service account only if they
# may act as that account: without this, attaching it would lock
# watchtower-deployer out of break glass. Only the guard then keeps the
# deployer from the VM's token.
retry_iam gcloud iam service-accounts add-iam-policy-binding "$BASTION_SA" --project "$GCP_PROJECT" \
  --member "serviceAccount:${DEPLOYER}" --role roles/iam.serviceAccountUser
bastion_start() {
  compute instances start "$BASTION" --zone "$BASTION_ZONE" ||
    die "${BASTION} is stopped and did not start, so break glass is down: rerun this, which starts it first"
}
# Up, or on its way: a run that failed between a stop and its start leaves it
# stopped with nothing below left to do, and nothing below starts it otherwise.
bastion_up() {
  local state=""
  for _ in $(seq 30); do
    state="$(compute instances describe "$BASTION" --zone "$BASTION_ZONE" --format 'value(status)')"
    case "$state" in
      RUNNING | PROVISIONING | STAGING) return 0 ;;
      TERMINATED)
        log "  ${BASTION} is stopped: starting it"
        bastion_start
        return 0
        ;;
      *) sleep 10 ;;
    esac
  done
  die "${BASTION} stayed ${state} for 5 minutes, so break glass is down"
}
# ruleset_state <sha> <since>: the guest attribute watchtower/ruleset on stdin;
# prints what came of that ruleset (pending, confirmed, rolled back, refused or
# failed), if it's no older than since, an epoch. Nothing when there is none: the
# attribute outlasts a stop, so a value alone says nothing about this boot.
# scripts/check-bastion.sh tests it.
ruleset_state() {
  { grep -xE '(pending|confirmed|rolled back|refused|failed) [0-9a-f]{64} at [0-9]+' || true; } |
    awk -v sha="$1" -v since="$2" '
      $(NF - 2) == sha && $NF + 0 >= since + 0 {
        state = $1
        if (NF == 5) state = $1 " " $2
      }
      END { print state }'
}
# bastion_attribute <key>: what the startup script reports. Never the serial
# output: any user can put a line there (logger, through rsyslog), and the guard
# keeps them from these.
bastion_attribute() {
  compute instances get-guest-attributes "$BASTION" --zone "$BASTION_ZONE" \
    --query-path "watchtower/$1" --format 'value(value)' 2>/dev/null || true
}
# When it last started, as an epoch: an attribute from before that is an earlier
# boot's.
bastion_started() {
  local started
  started="$(compute instances describe "$BASTION" --zone "$BASTION_ZONE" --format 'value(lastStartTimestamp)')"
  [[ -n "$started" ]] || die "${BASTION} says nothing of when it last started"
  date -d "$started" +%s
}
# The way to cancel a rollback by hand, as any account with OS Login on it.
confirm_by_hand="gcloud compute ssh ${BASTION} --zone ${BASTION_ZONE} --project ${GCP_PROJECT} --tunnel-through-iap --command 'touch /run/watchtower-ruleset/confirm'"
# The guest agent publishes the host keys once the VM has booted.
bastion_host_key() {
  compute instances get-guest-attributes "$BASTION" --zone "$BASTION_ZONE" \
    --query-path hostkeys/ssh-ed25519 --format 'value(value)' 2>/dev/null || true
}
# Dispatches bastion-confirm.yml through Gitea's API, for this branch: it logs
# in as the deployer and cancels the rollback. Says plainly if it can't, and
# never fails: then the rollback is what happens. The token goes through a
# pipe, never into a variable or an argument. The job pins the host key sent
# here: a new VM's isn't in the stack file yet.
bastion_dispatch() {
  local branch payload key
  branch="$(git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  key="$(bastion_host_key)"
  payload="$(mktemp)"
  jq -n --arg ref "$branch" --arg key "${key:+ssh-ed25519 ${key}}" '{ref: $ref, inputs: {host_key: $key}}' >"$payload"
  unset key
  if gopass show -o api/gitea >/dev/null &&
    gopass show -o api/gitea | sed 's/.*/header = "Authorization: token &"/' |
    curl -fsS -K - -H 'Content-Type: application/json' -X POST --data @"$payload" -o /dev/null \
      "${GITEA_API}/actions/workflows/bastion-confirm.yml/dispatches"; then
    log "  dispatched bastion-confirm.yml on ${branch}"
  else
    printf 'warning: could not dispatch bastion-confirm.yml on %s: Gitea is down, gopass is locked, or the branch is not pushed.\n' "${branch:-this checkout}" >&2
    printf 'warning: unless someone logs in, the bastion rolls this ruleset back in 10 minutes. To confirm by hand:\n  %s\n' "$confirm_by_hand" >&2
  fi
  rm -f "$payload"
}
# Waits for what comes of the ruleset at this boot, dispatching the job when it
# goes pending, and returns only if it's confirmed. A rollback takes 10 minutes
# and a reboot, so this outlasts it.
bastion_ruleset_wait() {
  local since=$1 state="" dispatched=""
  log "  waiting for ${BASTION}'s ruleset ${ruleset_sha:0:12}: it rolls back after 10 minutes unless confirmed"
  for _ in $(seq 100); do
    state="$(bastion_attribute ruleset | ruleset_state "$ruleset_sha" "$since")"
    case "$state" in
      confirmed)
        log "  ruleset confirmed"
        return 0
        ;;
      "rolled back")
        die "${BASTION} rolled ruleset ${ruleset_sha:0:12} back: it runs on its old ruleset, and as no one if it has no account yet. Rerun this: with a fixed config/bastion/nftables.conf, or with the same file to try it again (once Gitea can run bastion-confirm.yml; or confirm by hand: ${confirm_by_hand})"
        ;;
      refused)
        die "${BASTION} refused ruleset ${ruleset_sha:0:12} (see its serial output): it won't load or gives no guard, so what it ran stays. Fix config/bastion/nftables.conf and rerun"
        ;;
      failed)
        die "${BASTION} could not load ruleset ${ruleset_sha:0:12}, or could not put its old one back on disk (see its serial output, and \"A new ruleset\" in docs/runbook.md): it runs on the old ruleset or the floor from the kernel"
        ;;
      pending)
        if [[ -z "$dispatched" ]]; then
          dispatched=1
          bastion_dispatch
          # Even when the dispatch worked: the job may still fail, and a new
          # environment has no GCP_DEPLOYER_KEY for it yet.
          log "  if the job can't log in (a new environment has no GCP_DEPLOYER_KEY yet), confirm by hand: ${confirm_by_hand}"
        fi
        ;;
      *) ;;
    esac
    sleep 10
  done
  die "${BASTION} reported nothing final for ruleset ${ruleset_sha:0:12} within 15 minutes, so it still runs as it did: see its serial output, and rerun"
}
if ! exists instances describe "$BASTION" --zone "$BASTION_ZONE"; then
  compute instances create "$BASTION" --zone "$BASTION_ZONE" --machine-type e2-micro \
    --network-interface "subnet=${BASTION},private-network-ip=${BASTION_IP},no-address" \
    --image-family debian-13 --image-project debian-cloud \
    --boot-disk-size 10GB --boot-disk-type pd-standard \
    --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
    --no-service-account --no-scopes --tags "$BASTION" \
    --metadata enable-oslogin=TRUE,block-project-ssh-keys=TRUE,enable-guest-attributes=TRUE \
    --metadata-from-file "$bastion_files"
fi
# In place, and only when something differs. Stop and start keep the boot
# disk, so the SSH host key the stack pins stays; Secret Manager has no
# narrower scope than cloud-platform, so IAM (one secret, read only) is the
# fence.
bastion_up
# The deployer: OS Login on this VM (which includes looking it up), and an IAP
# tunnel to its port 22 only. Before anything below, which waits on its logging
# in.
retry_iam compute instances add-iam-policy-binding "$BASTION" --zone "$BASTION_ZONE" \
  --member "serviceAccount:${DEPLOYER}" --role roles/compute.osLogin
retry_iam gcloud projects add-iam-policy-binding "$GCP_PROJECT" \
  --member "serviceAccount:${DEPLOYER}" --role roles/iap.tunnelResourceAccessor \
  --condition "expression=destination.ip == \"${BASTION_IP}\" && destination.port == 22,title=${BASTION}-ssh,description=IAP to the bastion's SSH and nothing else"

current="$(compute instances describe "$BASTION" --zone "$BASTION_ZONE" --format json | jq -cS '{
  sa: (.serviceAccounts[0].email // ""), scopes: (.serviceAccounts[0].scopes // []),
  meta: ([.metadata.items[]? | select(.key | IN("startup-script", "watchtower-nftables", "watchtower-ruleset", "watchtower-alloy"))] | from_entries)}')"
want="$(jq -ncS --arg sa "$BASTION_SA" --rawfile s "${bastion_dir}/startup.sh" \
  --rawfile n "${bastion_dir}/nftables.conf" --rawfile r "${bastion_dir}/ruleset.sh" --rawfile a "$bastion_alloy" '{
  sa: $sa, scopes: ["https://www.googleapis.com/auth/cloud-platform"],
  meta: {"startup-script": $s, "watchtower-nftables": $n, "watchtower-ruleset": $r, "watchtower-alloy": $a}}')"
account_differs=""
[[ "$(jq -c 'del(.meta)' <<<"$current")" == "$(jq -c 'del(.meta)' <<<"$want")" ]] || account_differs=1
ruleset_before="$(bastion_attribute ruleset | ruleset_state "$ruleset_sha" 0)"
# A rerun after a rollback: this file again, even unchanged, since nothing need
# be wrong with it (Gitea was down). The VM takes a new value here to mean so,
# once.
retry_args=()
if [[ "$ruleset_before" == "rolled back" ]]; then
  log "  ${BASTION} rolled this ruleset back before: trying it again"
  retry_args=(--metadata "watchtower-nftables-retry=$(date -u +%s)")
fi
if [[ "$(jq -c .meta <<<"$current")" != "$(jq -c .meta <<<"$want")" || "${#retry_args[@]}" -gt 0 ]]; then
  log "  updating ${BASTION} in place: stop, its metadata, start"
  compute instances stop "$BASTION" --zone "$BASTION_ZONE"
  compute instances add-metadata "$BASTION" --zone "$BASTION_ZONE" --metadata-from-file "$bastion_files" "${retry_args[@]}"
  bastion_start
fi
# Every run, as the attribute doesn't age out: this boot's word on this file, so
# a run that changed nothing can't report success over a refused or unconfirmed
# ruleset.
boot_since="$(bastion_started)"
bastion_ruleset_wait "$boot_since"
if [[ -n "$account_differs" ]]; then
  # Never on a VM whose ruleset this boot hasn't confirmed (above): sshd's gate
  # would keep everyone out of a VM with a token and no guard, and with a bad
  # ruleset that means no way in at all. And not during its first apt install,
  # which this line comes after: a stop there can leave dpkg half done.
  log "  waiting for ${BASTION} to finish apt"
  guarded=""
  for _ in $(seq 90); do
    settled_at="$(bastion_attribute settled)"
    if [[ "$settled_at" =~ ^[0-9]+$ ]] && ((settled_at >= boot_since)); then
      guarded=1; break
    fi
    sleep 10
  done
  [[ -n "$guarded" ]] || die "${BASTION} didn't report that apt had finished within 15 minutes, so it still runs as no one: see its serial output, gcloud compute instances reset it if it is running, and rerun (a rerun starts it if it is stopped)"
  log "  attaching ${BASTION}'s account: stop, its account, start"
  compute instances stop "$BASTION" --zone "$BASTION_ZONE"
  compute instances set-service-account "$BASTION" --zone "$BASTION_ZONE" --service-account "$BASTION_SA" --scopes cloud-platform
  bastion_start
  # Asked again of the boot with the account, whose guard is what keeps a user
  # from the attribute. A VM with no guard before it can't vouch for itself: a
  # user could have written what the wait above read. Still pending here, it's
  # dispatched and waited on like any other, and anything but confirmed stops.
  boot_since="$(bastion_started)"
  bastion_ruleset_wait "$boot_since"
fi

nat_ip="$(compute addresses describe "${BASTION}-nat" --region "$BASTION_REGION" --format 'value(address)')"
# Never "Done" with break glass down.
bastion_up
host_key=""
for _ in $(seq 1 36); do
  host_key="$(bastion_host_key)"
  [[ -n "$host_key" ]] && break
  sleep 5
done
[[ -n "$host_key" ]] || die "${BASTION} published no ed25519 host key; re-run once it has booted"
# Into the stack file, in place of any earlier values, never to the terminal.
stack_tmp="$(mktemp)"
awk -v cidr="${nat_ip}/32" -v key="ssh-ed25519 ${host_key}" '
  function add() { print "  watchtower:breakGlassCidrs:"; print "    - " cidr; print "  watchtower:bastionHostKey: " key; done = 1 }
  /^  watchtower:bastionHostKey:/ { next }
  /^  watchtower:breakGlassCidrs:/ { skip = 1; next }
  skip && /^    - / { next }
  { skip = 0 }
  /^encryptionsalt:/ && !done { add() }
  { print }
  END { if (!done) add() }' "$stack_file" >"$stack_tmp"
cat "$stack_tmp" >"$stack_file"
rm -f "$stack_tmp"
unset host_key
bastion_as="$(compute instances describe "$BASTION" --zone "$BASTION_ZONE" --format 'value(serviceAccounts[0].email)')"

cat <<EOF

Done.
  State bucket : s3://${STATE_BUCKET} (admin key only)
  DNS          : zone ${ZONE} (${DOMAIN}.), delegated from ${PARENT_ZONE} in ${PARENT_PROJECT}
  Registry     : ${GAR_LOCATION}-docker.pkg.dev/${GCP_PROJECT}/${GAR_REPO}
  Secrets      : the ${#secret_ids[@]} the deploy reads, in ${GCP_PROJECT}; ${granted} readable by ${DEPLOYER},
                 which may add to the ${#deploy_written[@]} peer secrets and read back ${deploy_read_back[*]};
                 ${#agent_readers[@]} agent peers readable by their own service's identity
  Bastion      : ${BASTION} (${BASTION_ZONE}), SSH through IAP only; its traffic leaves from ${nat_ip}.
                 It runs as ${bastion_as}.
                 Its address and host key are in infra/cloud/Pulumi.prod.yaml
                 (breakGlassCidrs, bastionHostKey): commit any change and deploy.

Next (docs/runbook.md, "First deploy"):
  1. dig +short NS ${DOMAIN}
  2. scripts/rotate-gcp-key.sh deployer    # Gitea secret GCP_DEPLOYER_KEY
     scripts/rotate-gcp-key.sh caddy       # secret caddy-dns-key
     scripts/rotate-gcp-key.sh pusher      # secret gar-push-key + Gitea GAR_PUSH_KEY
     scripts/rotate-gcp-key.sh puller      # secret gar-pull-key
  3. scripts/secret.sh check               # every secret has a value
EOF
