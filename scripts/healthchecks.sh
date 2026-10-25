#!/usr/bin/env bash
# Create or update the Healthchecks.io checks the deploy pings, and store
# their ping URLs in Secret Manager:
#   - one check per host, as healthchecks-host-urls: one JSON object of host
#     name to URL, of which the deploy gives each host only its own entry
#     (roles/health). Each host pings its check every 5 minutes; the check
#     emails when a host reports a problem twice in a row or goes 15 minutes
#     without reporting. Hosts are the proxy and watchtower-1..nodeCount
#     (infra/cloud/Pulumi.prod.yaml).
#   - watchtower-deploy, as healthchecks-deploy-url: every deploy run pings
#     it at the end, /fail when a job failed, which emails at once; the
#     scheduled run (05:00 UTC, Monday to Saturday) not reporting by 07:00
#     emails too.
#
#   scripts/healthchecks.sh
#
# Re-run after changing nodeCount: checks are matched by name and updated in
# place, never deleted, and a check's ping URL never changes.
#
# Uses the project's API key (healthchecks-jasonmross-dev-api-key, from
# gopass). Only the owner holds it: the deploy gets ping URLs, which can
# report but not pause, change or delete a check. Needs gopass, jq, curl and
# what scripts/secret.sh needs.

set -euo pipefail

API="https://healthchecks.io/api/v3"
TAGS="observability watchtower host"
TIMEOUT=300 # seconds between pings (watchtower-health.timer)
GRACE=600   # then this long before a missed ping alerts
DEPLOY_SCHEDULE="0 5 * * 1-6" # deploy.yml's schedule, in UTC
DEPLOY_GRACE=7200             # a run takes well under an hour

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stack_file="${repo_root}/infra/cloud/Pulumi.prod.yaml"

nodes="$(sed -n 's/^  watchtower:nodeCount: "\{0,1\}\([0-9]*\)"\{0,1\}$/\1/p' "$stack_file")"
hosts=(watchtower-proxy)
for ((i = 1; i <= ${nodes:-3}; i++)); do hosts+=("watchtower-${i}"); done

work="$(mktemp -d)"
chmod 0700 "$work"
trap 'find "$work" -type f -exec shred -u {} + 2>/dev/null; rm -rf "$work"' EXIT
umask 077

# The key goes to curl in a config file, never on a command line.
key="$(gopass show -o watchtower/healthchecks-jasonmross-dev-api-key)"
printf 'header = "X-Api-Key: %s"\n' "$key" >"${work}/auth"
unset key
api() { curl -fsS -m 20 --retry 3 -K "${work}/auth" -H 'Content-Type: application/json' "$@"; }

# The check ${work}/spec.json describes, created or brought up to date, into
# ${work}/check.json.
upsert() {
  local url
  # unique: an existing check of this name comes back instead of a new one.
  jq '. + {unique: ["name"]}' "${work}/spec.json" | api -X POST --data @- "${API}/checks/" >"${work}/check.json"
  # Bring an existing check's settings up to date too.
  url="$(jq -r .update_url "${work}/check.json")"
  printf 'url = "%s"\n' "$url" | api -K - -X POST --data @"${work}/spec.json" >/dev/null
  echo "check $(jq -r .name "${work}/check.json"): $(jq -r .status "${work}/check.json")"
}

: >"${work}/urls"
for host in "${hosts[@]}"; do
  jq -n --arg name "$host" --arg tags "$TAGS" --argjson timeout "$TIMEOUT" --argjson grace "$GRACE" '{
    name: $name, slug: $name, tags: $tags, timeout: $timeout, grace: $grace, channels: "*",
    desc: ("Health of " + $name + ": every service active and ready, the data volume mounted, disks under 90%, SELinux enforcing. Pinged every 5 minutes by watchtower-health.timer; /fail after two unhealthy runs in a row. docs/runbook.md, \"Host health\".")
  }' >"${work}/spec.json"
  upsert
  jq -r --arg host "$host" '[$host, .ping_url] | @tsv' "${work}/check.json" >>"${work}/urls"
done

jq -R -s -c 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add' "${work}/urls" |
  "${repo_root}/scripts/secret.sh" put healthchecks-host-urls
echo "Deploy to hand each host its URL; until a host first pings, its check stays \"new\" and never alerts."

jq -n --arg schedule "$DEPLOY_SCHEDULE" --argjson grace "$DEPLOY_GRACE" '{
  name: "watchtower-deploy", slug: "watchtower-deploy", tags: "observability watchtower deploy",
  schedule: $schedule, tz: "UTC", grace: $grace, channels: "*",
  desc: "The deploy workflow (.gitea/workflows/deploy.yml): every run pings at the end, /fail as soon as a job failed. It runs at 05:00 UTC Monday to Saturday (not on Sunday, the hosts'"'"' reboot morning) to rebuild the Alpine images with the day'"'"'s packages, so no ping by 07:00 means that run never came. The ping body links the run."
}' >"${work}/spec.json"
upsert
jq -r .ping_url "${work}/check.json" | "${repo_root}/scripts/secret.sh" put healthchecks-deploy-url
