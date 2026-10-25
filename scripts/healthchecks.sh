#!/usr/bin/env bash
# Create or update one Healthchecks.io check per host, and store their ping
# URLs as the healthchecks-host-urls secret: one JSON object of host name to
# URL, of which the deploy gives each host only its own entry (roles/health).
#
#   scripts/healthchecks.sh
#
# Each host pings its check every 5 minutes; the check emails when a host
# reports a problem twice in a row or goes 15 minutes without reporting.
# Hosts are the proxy and watchtower-1..nodeCount (infra/cloud/Pulumi.prod.yaml).
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

: >"${work}/urls"
for host in "${hosts[@]}"; do
  jq -n --arg name "$host" --arg tags "$TAGS" --argjson timeout "$TIMEOUT" --argjson grace "$GRACE" '{
    name: $name, slug: $name, tags: $tags, timeout: $timeout, grace: $grace, channels: "*",
    desc: ("Health of " + $name + ": every service active and ready, the data volume mounted, disks under 90%, SELinux enforcing. Pinged every 5 minutes by watchtower-health.timer; /fail after two unhealthy runs in a row. docs/runbook.md, \"Host health\".")
  }' >"${work}/spec.json"
  # unique: an existing check of this name comes back instead of a new one.
  jq '. + {unique: ["name"]}' "${work}/spec.json" | api -X POST --data @- "${API}/checks/" >"${work}/check.json"
  # Bring an existing check's settings up to date too.
  url="$(jq -r .update_url "${work}/check.json")"
  printf 'url = "%s"\n' "$url" | api -K - -X POST --data @"${work}/spec.json" >/dev/null
  jq -r --arg host "$host" '[$host, .ping_url] | @tsv' "${work}/check.json" >>"${work}/urls"
  echo "check ${host}: $(jq -r .status "${work}/check.json")"
done

jq -R -s -c 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add' "${work}/urls" |
  "${repo_root}/scripts/secret.sh" put healthchecks-host-urls
echo "Deploy to hand each host its URL; until a host first pings, its check stays \"new\" and never alerts."
