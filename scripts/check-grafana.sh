#!/usr/bin/env bash
# Checks Grafana's rendered provisioning the way Grafana reads it, so a mistake
# fails the PR and never Grafana's start on a node: an alerting file Grafana
# can't load stops it from starting. Render first:
#
#   (cd ansible && ansible-playbook -i inventory/hosts.sample.yml playbooks/render.yml)
#   scripts/check-grafana.sh            # docker; CONTAINER_RUNTIME=podman locally
#
# On ansible/.render/watchtower-1/grafana/provisioning (every node's is the same):
#   structure  scripts/check-grafana-provisioning.py: the files parse; each rule
#              has a short unique uid, provisioned datasources, a condition among
#              its queries and telemetry="true"; one rule group per source; the
#              contact point reads the ping URL from the secret the quadlet
#              mounts; the payload carries healthchecks.sh's keywords
#   PromQL     promtool check rules, on every Mimir query (rules' and the
#              dashboard's, its variables filled in)
#   LogQL      the pinned Loki's own parser (/loki/api/v1/format_query)
#   Grafana    the pinned Grafana starts on it twice: as a deploy with the ping
#              URL has it (the notifications file, and a stand-in URL in the
#              secret) and as one without (no notifications file). Each time it
#              must stay up, log no provisioning error, and report through its
#              API every rule as written, the contact points and policy tree only
#              with the file, and the dashboard in the Telemetry folder.
#
# Images: Grafana and Loki at the digests the hosts run (group_vars/all/
# images.yml); promtool, and busybox's wget and sh for the API calls, from the
# Prometheus image below. Files go in with `cp`, not bind mounts: on the Gitea
# runners the daemon is Docker-in-Docker and can't see this filesystem.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
prov="${repo_root}/ansible/.render/watchtower-1/grafana/provisioning"
images="${repo_root}/ansible/inventory/group_vars/all/images.yml"
rt="${CONTAINER_RUNTIME:-docker}"
# promtool, and a busybox with wget and sh. Newest stable release, 2026-11-06:
#   skopeo inspect --raw docker://docker.io/prom/prometheus:v3.16.0 | sha256sum
PROMETHEUS_IMAGE="${PROMETHEUS_IMAGE:-docker.io/prom/prometheus:v3.16.0@sha256:e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06}"
# Not a real ping URL: nothing is ever sent to it.
STAND_IN_URL="https://hc-ping.invalid/stand-in-for-the-ping-url"
SECRET_NAME=grafana-telemetry-alert-url

[[ -d "$prov" ]] || { echo "nothing rendered in ${prov}; run playbooks/render.yml first" >&2; exit 1; }
image() { sed -n "s/^  $1: //p" "$images"; }

work="$(mktemp -d)"
# Every container this run makes carries this label, so the cleanup finds them
# all, whichever subshell made them.
run_label="watchtower-check-grafana=$$"
# shellcheck disable=SC2329 # called by the EXIT trap
cleanup() {
  local ids
  ids="$("$rt" ps -aq --filter "label=${run_label}" 2>/dev/null || true)"
  # One at a time, newest first: a container another one shares a network
  # namespace with can only go after it (podman refuses).
  for c in $ids; do "$rt" rm -f "$c" >/dev/null 2>&1 || true; done
  [[ "$rt" != podman ]] || podman secret rm "$SECRET_NAME-check" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
fail=0

# 1. Structure, and every query written out for its parser.
python3 "${repo_root}/scripts/check-grafana-provisioning.py" static "$prov" "$work/out" || fail=1

# 2. PromQL.
cid="$("$rt" create --label "$run_label" --network none --entrypoint /bin/promtool "$PROMETHEUS_IMAGE" check rules /tmp/promql-rules.yml)"
"$rt" cp "$work/out/promql-rules.yml" "${cid}:/tmp/promql-rules.yml"
if out="$("$rt" start --attach "$cid" 2>&1)"; then
  echo "ok    PromQL: promtool parses every Mimir query"
else
  echo "FAIL  PromQL"
  printf '%s\n' "$out" | tail -25 | sed 's/^/      /'
  fail=1
fi

# A busybox in <container>'s network namespace, running <script> (sh -c) with
# <file> copied to /tmp/in if given; removed as soon as it's done, so it never
# holds up the removal of the container it shares a namespace with.
in_netns() { # container script [file]
  local c rc=0
  c="$("$rt" create --label "$run_label" --network "container:$1" --entrypoint /bin/sh "$PROMETHEUS_IMAGE" -c "$2")"
  [[ -z "${3:-}" ]] || "$rt" cp "$3" "${c}:/tmp/in"
  "$rt" start --attach "$c" || rc=$?
  "$rt" rm -f "$c" >/dev/null 2>&1 || true
  return "$rc"
}

# wait_http <container> <url path> <port> <seconds>: until it answers 200, or
# the container exits.
wait_http() {
  local i
  for ((i = 0; i < $4; i += 3)); do
    [[ "$("$rt" inspect -f '{{.State.Running}}' "$1")" == true ]] || return 1
    if in_netns "$1" "wget -q -O /dev/null http://127.0.0.1:$3$2" >/dev/null 2>&1; then return 0; fi
    sleep 3
  done
  return 1
}

# 3. LogQL, by the Loki the hosts run (its single-binary local config).
loki="$("$rt" create --label "$run_label" "$(image loki)" -config.file=/etc/loki/local-config.yaml)"
"$rt" start "$loki" >/dev/null
# Each line of /tmp/in: a name, a tab, the URL-encoded query. format_query
# answers 400 to one that doesn't parse.
# shellcheck disable=SC2016 # expanded by the sh in the container
parse_logql='
  bad=0
  while IFS="$(printf "\t")" read -r name query; do
    wget -q -O /dev/null "http://127.0.0.1:3100/loki/api/v1/format_query?query=${query}" || { echo "does not parse: ${name}"; bad=1; }
  done </tmp/in
  exit "$bad"'
if ! wait_http "$loki" /ready 3100 120; then
  echo "FAIL  LogQL: Loki never became ready"
  "$rt" logs "$loki" 2>&1 | tail -15 | sed 's/^/      /'
  fail=1
elif out="$(in_netns "$loki" "$parse_logql" "$work/out/logql.tsv" 2>&1)"; then
  echo "ok    LogQL: Loki parses every Loki query ($(wc -l <"$work/out/logql.tsv"))"
else
  echo "FAIL  LogQL"
  printf '%s\n' "$out" | sed 's/^/      /'
  fail=1
fi
"$rt" rm -f "$loki" >/dev/null

# 4. Grafana, with and without the notifications file.
grafana_run() { # variant
  local variant=$1 g dir="$work/$1" api="$work/$1/api" secret_args=()
  mkdir -p "$dir/provisioning" "$api"
  cp -R "$prov/." "$dir/provisioning/"
  [[ "$variant" == full ]] || rm "$dir/provisioning/alerting/telemetry-notifications.yaml"
  printf '%s' "$STAND_IN_URL" >"$api/stand-in-url"
  if [[ "$variant" == full && "$rt" == podman ]]; then
    # podman puts a tmpfs on /run: the secret has to be a secret.
    podman secret create --replace "$SECRET_NAME-check" "$api/stand-in-url" >/dev/null
    secret_args=(--secret "$SECRET_NAME-check,target=/run/secrets/$SECRET_NAME,type=mount,uid=472,mode=0400")
  fi
  g="$("$rt" create --label "$run_label" "${secret_args[@]}" -e GF_SECURITY_ADMIN_PASSWORD=check "$(image grafana)")"
  "$rt" cp "$dir/provisioning/." "${g}:/etc/grafana/provisioning"
  if [[ "$variant" == full && "$rt" != podman ]]; then
    # docker has no secrets outside swarm, and leaves the image's /run alone:
    # a copy will do. /run/secrets doesn't exist yet, so cp makes it from the
    # directory.
    mkdir -p "$dir/secrets"
    cp "$api/stand-in-url" "$dir/secrets/$SECRET_NAME"
    chmod -R a+rX "$dir/secrets"
    "$rt" cp "$dir/secrets" "${g}:/run/secrets"
  fi
  "$rt" start "$g" >/dev/null
  if ! wait_http "$g" /api/health 3000 180; then
    echo "FAIL  grafana ($variant): it did not start"
    # Its last words name the cause; the modules it stopped only repeat it.
    # grep, not rg: the runners don't install ripgrep.
    "$rt" logs "$g" 2>&1 | grep -v -e 'logger=plugin' -e 'Failed to stop all modules' -e 'msg="Module failed"' |
      grep -E 'level=error|^Error' | tail -4 | cut -c1-600 | sed 's/^/      /'
    fail=1
    return
  fi
  # The provisioners' errors (dashboards' don't stop Grafana; alerting's do).
  if "$rt" logs "$g" 2>&1 | grep 'logger=provisioning' | grep -q 'level=error'; then
    echo "FAIL  grafana ($variant): provisioning logged errors"
    "$rt" logs "$g" 2>&1 | grep 'logger=provisioning' | grep 'level=error' | tail -8 | cut -c1-400 | sed 's/^/      /'
    fail=1
  fi
  local path name
  for pair in alert-rules.json=/api/v1/provisioning/alert-rules contact-points.json=/api/v1/provisioning/contact-points \
    policies.json=/api/v1/provisioning/policies dashboard.json=/api/dashboards/uid/telemetry-fleet; do
    name="${pair%%=*}" path="${pair#*=}"
    in_netns "$g" "wget -q -O - --header 'Authorization: Basic YWRtaW46Y2hlY2s=' http://127.0.0.1:3000${path}" >"$api/$name" 2>/dev/null || true
  done
  python3 "${repo_root}/scripts/check-grafana-provisioning.py" api "$work/out" "$variant" "$api" || fail=1
  "$rt" rm -f "$g" >/dev/null
}
grafana_run full
grafana_run bare

exit "$fail"
