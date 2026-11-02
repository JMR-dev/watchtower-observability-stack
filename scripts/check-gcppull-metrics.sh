#!/usr/bin/env bash
# Runs the metrics half of the GCP pull's rendered Alloy config over a made-up metrics
# page, and checks what would reach Mimir: a pod's name and a NAT address never in a
# label (docs/client-telemetry.md, "Labels"), the labels each series should have, and
# this Alloy's own health from every node.
#
#   (cd ansible && ansible-playbook -i inventory/hosts.sample.yml playbooks/render.yml)
#   scripts/check-gcppull-metrics.sh [config] [fixture]
#   (defaults: ansible/.render/watchtower-3/gcppull/config.alloy, the node with the
#    exporter, and config/alloy/testdata/gcppull.metrics)
#
# The config runs with these changes only:
#   - the two log sources are left out, so nothing is pulled;
#   - prometheus.exporter.gcp is left out, and its scrape reads the fixture instead,
#     served on loopback;
#   - remote_write's receiver is prometheus.echo, which is why this runs at
#     --stability.level=experimental; the config itself needs no such flag;
#   - scrapes come every 2 seconds, not every 5 minutes.
#
# <fixture>.expect holds every Cloud Monitoring series that must come out, exactly, and
# no other may. The checks read each series's labels but `instance`, which here is
# only this test's port, not its value or time.
#
# Needs alloy, jq, curl and python3. Touches a temp directory and loopback; no GCP,
# no Mimir, no credentials.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config="${1:-${repo_root}/ansible/.render/watchtower-3/gcppull/config.alloy}"
fixture="${2:-${repo_root}/config/alloy/testdata/gcppull.metrics}"
expect="${fixture}.expect"
http_port="${ALLOY_TEST_PORT:-12386}"
page_port="$((http_port + 1))"

fail() { echo "gcp pull metrics check: $*" >&2; exit 1; }
for f in "$config" "$fixture" "$expect"; do
  [[ -f "$f" ]] || fail "need ${f} (render first: ansible/playbooks/render.yml)"
done

# What the echo below stands in for: remote_write's own labels, and that it has them.
grep -qF 'external_labels = {service = "gitea-ci", env = "production"}' "$config" ||
  fail "remote_write doesn't label its series service and env"

work="$(mktemp -d)"
pid=
server=
cleanup() {
  [[ -z "$pid" ]] || kill "$pid" 2>/dev/null || true
  [[ -z "$server" ]] || kill "$server" 2>/dev/null || true
  [[ -z "$pid" ]] || wait "$pid" 2>/dev/null || true
  [[ -z "$server" ]] || wait "$server" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

mkdir "${work}/www"
cp "$fixture" "${work}/www/metrics"
python3 -m http.server "$page_port" --bind 127.0.0.1 --directory "${work}/www" >/dev/null 2>&1 &
server=$!

# --- The harness: the config with only the changes in the header.
awk '
  /^loki\.source\.gcplog / || /^prometheus\.exporter\.gcp / || /^prometheus\.remote_write / { skip = 1; next }
  skip { if (/^}/) skip = 0; next }
  /^\tformat = "logfmt"$/ || /^\tformat +=/ { print "\tformat = \"json\""; next }
  { print }
' "$config" |
  sed -E \
    -e "s/^([[:space:]]*targets[[:space:]]*=[[:space:]]*)prometheus\.exporter\.gcp\.gitea_ci\.targets$/\1[{\"__address__\" = \"127.0.0.1:${page_port}\"}]/" \
    -e 's/prometheus\.remote_write\.watchtower\.receiver/prometheus.echo.out.receiver/' \
    -e '/^[[:space:]]*scrape_timeout[[:space:]]*=/d' \
    -e 's/^([[:space:]]*)scrape_interval[[:space:]]*=.*/\1scrape_interval = "2s"\n\1scrape_timeout = "1s"/' \
    >"${work}/harness.alloy"
printf '\nprometheus.echo "out" { }\n' >>"${work}/harness.alloy"
grep -qF "127.0.0.1:${page_port}" "${work}/harness.alloy" || fail "no exporter scrape in ${config}: give it the exporter node's config"

alloy run --stability.level=experimental --server.http.listen-addr="127.0.0.1:${http_port}" \
  --storage.path="${work}/data" --disable-reporting "${work}/harness.alloy" >"${work}/alloy.log" 2>&1 &
pid=$!

# --- Each series that came out, without its value and time.
out="${work}/series.txt"
show() {
  jq -r 'select(.component_id == "prometheus.echo.out") | .metrics' "${work}/alloy.log" 2>/dev/null |
    grep -v '^#' | sed -E -e 's/\} .*$/}/' -e 's/instance="[^"]*",?//' | sort -u >"$out" || true
}
for _ in $(seq 60); do
  show
  if [[ "$(grep -c '^stackdriver_' "$out" || true)" -ge "$(wc -l <"$expect")" ]] &&
    grep -q 'job="alloy"' "$out"; then
    break
  fi
  kill -0 "$pid" 2>/dev/null || { tail -20 "${work}/alloy.log" >&2; fail "alloy exited"; }
  sleep 0.5
done
[[ -z "${SCRUB_SHOW:-}" ]] || cat "$out"

bad=0
grep '^stackdriver_' "$out" >"${work}/gcp.txt" || true
if ! diff -u "$expect" "${work}/gcp.txt"; then
  echo "the Cloud Monitoring series aren't as expected (above)"
  bad=1
fi
for pattern in 'pod_name=' 'nat_ip=' '198\.51\.100' 'gitea-job-'; do
  if grep -qE -- "$pattern" "$out"; then
    echo "leaked /${pattern}/: $(grep -E -- "$pattern" "$out" | head -n 3)"
    bad=1
  fi
done
# This Alloy's own health: under the node's name, not the shared host="gcp".
grep -qE '^up\{[^}]*host="watchtower-[0-9]+"[^}]*job="alloy"' "$out" ||
  { echo "this Alloy's own metrics don't come out under the node's name"; bad=1; }
grep -qE '^up\{[^}]*host="gcp"[^}]*job="integrations/gcp"' "$out" ||
  { echo "the Cloud Monitoring scrape doesn't come out as host=gcp, job=integrations/gcp"; bad=1; }
[[ "$bad" -eq 0 ]] || fail "$(basename "$config") would send what it shouldn't (above)"
echo "gcp pull metrics check: $(wc -l <"${work}/gcp.txt") Cloud Monitoring series as expected, no pod name or NAT address"
