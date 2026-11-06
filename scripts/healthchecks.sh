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
#   - watchtower-bastion, as healthchecks-bastion-url: the break-glass bastion
#     reads it itself (scripts/bootstrap.sh lets it, and nothing else), and pings
#     after each boot and at 05:00 UTC every day, once its metadata guard is
#     loaded and sshd is active (config/bastion/startup.sh). So one that didn't
#     come back from its 04:00 reboot emails by 07:00.
#   - watchtower-telemetry-alerts, as healthchecks-telemetry-alert-url: down
#     while any Grafana telemetry alert fires (roles/grafana). Grafana POSTs
#     every notification of its one telemetry group to the plain ping URL, and
#     the check sorts them by a keyword in the body: TELEMETRY-ALERTS-FIRING is a
#     failure (down, emails), TELEMETRY-ALERTS-RESOLVED a success (up, emails),
#     anything else is ignored. Pings come only on a change and while something
#     fires, so its period is the longest Healthchecks.io allows (a year, then a
#     year's grace): silence means nothing is firing, not that Grafana is gone
#     (each node's own check covers that). Until the first alert it stays "new".
#     It then reads the secret's IAM policy (read-only) and says whether the
#     deployer may read it; if not, scripts/bootstrap.sh must run next, or every
#     deploy warns and goes on without the notifications.
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
BASTION_TIMEOUT=86400         # seconds between pings (watchtower-ping.timer)
BASTION_GRACE=7200            # then this long before a missed ping alerts
# The telemetry alerts' check. The keywords are the first line of the body
# Grafana sends (roles/grafana/templates/telemetry-notifications.yaml.j2;
# scripts/check-grafana.sh and a Go test keep the two the same). Case-sensitive.
TELEMETRY_SUCCESS_KW="TELEMETRY-ALERTS-RESOLVED"
TELEMETRY_FAILURE_KW="TELEMETRY-ALERTS-FIRING"
TELEMETRY_TIMEOUT=31536000 # a year, Healthchecks.io's longest: no ping is no news
TELEMETRY_GRACE=31536000

# Where the secrets are (scripts/secret.sh's default too).
GCP_PROJECT="${GCP_PROJECT:-watchtower-observe}"

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

jq -n --argjson timeout "$BASTION_TIMEOUT" --argjson grace "$BASTION_GRACE" '{
  name: "watchtower-bastion", slug: "watchtower-bastion", tags: "observability watchtower bastion",
  timeout: $timeout, grace: $grace, channels: "*",
  desc: "The break-glass bastion: pinged after each boot and at 05:00 UTC every day, only with its metadata guard loaded and sshd active. A missed ping means it did not come back from a reboot, or is up without one of those. docs/runbook.md, \"The bastion with SSH gone\"."
}' >"${work}/spec.json"
upsert
jq -r .ping_url "${work}/check.json" | "${repo_root}/scripts/secret.sh" put healthchecks-bastion-url
echo "Run scripts/bootstrap.sh to let the bastion read its URL. Until it first pings, its check stays \"new\" and never alerts."

# POST only (Grafana's webhook); an unmatched body is ignored, never a failure.
jq -n --argjson timeout "$TELEMETRY_TIMEOUT" --argjson grace "$TELEMETRY_GRACE" \
  --arg success "$TELEMETRY_SUCCESS_KW" --arg failure "$TELEMETRY_FAILURE_KW" '{
  name: "watchtower-telemetry-alerts", slug: "watchtower-telemetry-alerts", tags: "observability watchtower telemetry",
  timeout: $timeout, grace: $grace, channels: "*", methods: "POST",
  filter_http_body: true, filter_default_fail: false, start_kw: "", success_kw: $success, failure_kw: $failure,
  desc: ("Down while any Grafana telemetry alert fires: the services that ship telemetry to watchtower (ansible/inventory/group_vars/all/telemetry.yml). Grafana posts each notification of its one telemetry group here; a body with " + $failure + " is a failure, one with " + $success + " (everything resolved) a success. The body lists what fires. docs/runbook.md, \"Telemetry alerts\".")
}' >"${work}/spec.json"
upsert
jq -r .ping_url "${work}/check.json" | "${repo_root}/scripts/secret.sh" put healthchecks-telemetry-alert-url

# The deploy reads the URL as an optional secret, and one it may not read only
# warns: it goes on without notifications. So say here, where the owner is
# watching, whether the deployer may read it. Read-only: bootstrap.sh owns IAM.
deployer="serviceAccount:watchtower-deployer@${GCP_PROJECT}.iam.gserviceaccount.com"
if ! gcloud secrets get-iam-policy healthchecks-telemetry-alert-url --project "$GCP_PROJECT" --format json >"${work}/policy.json"; then
  echo "WARNING: could not read healthchecks-telemetry-alert-url's IAM policy, so whether the deploy may read it is unknown: see that it has roles/secretmanager.secretAccessor for ${deployer#serviceAccount:}, or run scripts/bootstrap.sh." >&2
elif jq -e --arg m "$deployer" 'any(.bindings[]?; .role == "roles/secretmanager.secretAccessor" and any(.members[]; . == $m))' "${work}/policy.json" >/dev/null; then
  echo "The deployer may read healthchecks-telemetry-alert-url: deploy to give Grafana its URL. Until an alert first fires, its check stays \"new\"."
else
  echo "==> NEXT: run scripts/bootstrap.sh. ${deployer#serviceAccount:} may not read healthchecks-telemetry-alert-url yet, so every deploy warns and goes on without the telemetry alerts' notifications until bootstrap.sh grants it." >&2
fi
