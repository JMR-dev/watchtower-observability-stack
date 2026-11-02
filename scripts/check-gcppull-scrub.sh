#!/usr/bin/env bash
# Runs the GCP pull's rendered Alloy config over made-up Cloud Logging entries,
# through Alloy's real loki.source.gcplog, and checks what would ship. Nothing on
# watchtower scrubs later, so this pipeline is all there is between Gitea CI's logs
# and storage (docs/client-telemetry.md).
#
#   (cd ansible && ansible-playbook -i inventory/hosts.sample.yml playbooks/render.yml)
#   scripts/check-gcppull-scrub.sh [config] [fixture]
#   (defaults: ansible/.render/watchtower-1/gcppull/config.alloy,
#    config/alloy/testdata/gcppull.log)
#
# Like scripts/check-alloy-scrub.sh, with these differences: the source can't read a
# file, and what it does with __gcp_* is part of what is tested, so the config runs
# whole, with these changes only:
#   - the first source pulls nothing: it takes Pub/Sub push messages on loopback,
#     with the labels and settings the config gave it; the second is left out;
#   - logs go to loki.echo, not Loki.
#
# The fixture holds one LogEntry JSON a line, and # comments. Each goes in as a
# Pub/Sub message.
#   <fixture minus .log>.expect     every line that may come out, whole, as
#                                   labels<TAB>structured metadata<TAB>line,
#                                   and nothing else may. Its last line must be the
#                                   fixture's last entry: the run ends when it does.
#   <fixture minus .log>.forbidden  grep -E patterns that nothing that comes out may
#                                   match, in a label, in metadata or in the line.
#
# Also checks: the shared scrub block is byte for byte the example's; both projects
# are pulled; and the Cloud Monitoring exporter is on one node's config only.
#
# SCRUB_SHOW=1 prints what came out. Needs alloy, jq and curl. Touches a temp
# directory and loopback; no GCP, no credentials.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
render="${repo_root}/ansible/.render"
config="${1:-${render}/watchtower-1/gcppull/config.alloy}"
fixture="${2:-${repo_root}/config/alloy/testdata/gcppull.log}"
example="${repo_root}/config/alloy/config.alloy.example"
expect="${fixture%.log}.expect"
forbidden="${fixture%.log}.forbidden"
http_port="${ALLOY_TEST_PORT:-12396}"
push_port="$((http_port + 1))"

fail() { echo "gcp pull check: $*" >&2; exit 1; }
for f in "$config" "$fixture" "$expect" "$forbidden" "$example"; do
  [[ -f "$f" ]] || fail "need ${f} (render first: ansible/playbooks/render.yml)"
done

work="$(mktemp -d)"
pid=
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

# --- What the rendered configs must say, before running one.
markers() { sed -n '/^\/\/ scrub: begin/,/^\/\/ scrub: end/p' "$1"; }
if ! diff -u <(markers "$example") <(markers "$config") >"${work}/block.diff"; then
  cat "${work}/block.diff" >&2
  fail "the scrub block isn't the example's, byte for byte"
fi
[[ -n "$(markers "$config")" ]] || fail "no scrub block in ${config}"
for project in gitea-496920 gitea-ci-781388; do
  grep -qF "project_id             = \"${project}\"" "$config" || fail "${project} isn't pulled"
done
if [[ -d "$render" ]]; then
  with_exporter="$(grep -l '^prometheus\.exporter\.gcp ' "$render"/*/gcppull/config.alloy || true)"
  [[ "$with_exporter" == "${render}/watchtower-3/gcppull/config.alloy" ]] ||
    fail "the exporter should be on watchtower-3 alone, and is on: ${with_exporter:-none}"
fi

# --- The harness: the config with only the changes in the header.
awk -v http="$push_port" '
  # The second source and loki.write go, each up to its closing brace.
  /^loki\.source\.gcplog / { sources++; if (sources > 1) { skip = 1; next } }
  /^loki\.write / { skip = 1; next }
  skip { if (/^}/) skip = 0; next }
  /^prometheus\.|^discovery\./ { fail_exporter = 1 }
  # Push, not pull: no project, no subscription, no limit.
  /^\tpull \{$/ {
    print "\tpush {"
    print "\t\thttp {"
    print "\t\t\tlisten_address = \"127.0.0.1\""
    print "\t\t\tlisten_port    = " http
    print "\t\t}"
    next
  }
  /^\t\tproject_id / || /^\t\tsubscription / { next }
  /^\t\tlimit \{$/ { in_limit = 1; next }
  in_limit { if (/^\t\t\}$/) in_limit = 0; next }
  /^\tformat = "logfmt"$/ || /^\tformat +=/ { print "\tformat = \"json\""; next }
  { print }
  END { if (fail_exporter) exit 3 }
' "$config" |
  sed -E 's/^([[:space:]]*forward_to[[:space:]]*=[[:space:]]*)\[loki\.write\.watchtower\.receiver\]$/\1[loki.echo.out.receiver]/' \
    >"${work}/harness.alloy" || fail "give it a node's config without the exporter (watchtower-1)"
printf '\nloki.echo "out" { }\n' >>"${work}/harness.alloy"

alloy run --server.http.listen-addr="127.0.0.1:${http_port}" --storage.path="${work}/data" \
  --disable-reporting "${work}/harness.alloy" >"${work}/alloy.log" 2>&1 &
pid=$!

for _ in $(seq 60); do
  curl -fsS -o /dev/null "http://127.0.0.1:${http_port}/-/ready" 2>/dev/null && break
  kill -0 "$pid" 2>/dev/null || { tail -20 "${work}/alloy.log" >&2; fail "alloy exited"; }
  sleep 0.5
done

# --- Every entry, in order, as one Pub/Sub push message.
total=0
while IFS= read -r entry; do
  [[ -z "$entry" || "$entry" == \#* ]] && continue
  total=$((total + 1))
  jq -ne --arg data "$(printf '%s' "$entry" | base64 -w0)" --arg id "$total" \
    '{message: {data: $data, message_id: $id, attributes: {}}, subscription: "projects/fixture/subscriptions/watchtower-logs-pull"}' \
    >"${work}/message.json"
  code="$(curl -sS -o "${work}/answer" -w '%{http_code}' -X POST --data-binary "@${work}/message.json" \
    "http://127.0.0.1:${push_port}/gcp/api/v1/push")"
  [[ "$code" == 204 ]] || { cat "${work}/answer" >&2; fail "entry ${total} was answered ${code}: ${entry}"; }
done <"$fixture"

# --- What came out: labels, structured metadata and line, a line each. A line that
# is JSON gets its keys sorted, since Alloy writes them in no fixed order.
out="${work}/out.txt"
show() {
  jq -r 'def sorted: walk(if type == "object" then to_entries | sort_by(.key) | from_entries else . end);
    select(.component_id == "loki.echo.out")
    | .entry as $line
    | [.labels, .structured_metadata, (try ($line | fromjson | sorted | tojson) catch $line)]
    | join("\t")' "${work}/alloy.log" 2>/dev/null >"$out" || true
}
last="$(tail -n 1 "$expect")"
for _ in $(seq 60); do
  show
  grep -qxF -- "$last" "$out" && break
  kill -0 "$pid" 2>/dev/null || { tail -20 "${work}/alloy.log" >&2; fail "alloy exited"; }
  sleep 0.5
done
# Anything still on its way that shouldn't be.
sleep 1
show
[[ -z "${SCRUB_SHOW:-}" ]] || cat "$out"

bad=0
while IFS= read -r line; do
  grep -qxF -- "$line" "$out" || { echo "didn't come out as expected: ${line}"; bad=1; }
done <"$expect"
while IFS= read -r line; do
  grep -qxF -- "$line" "$expect" || { echo "shipped, and not expected: ${line}"; bad=1; }
done <"$out"
while IFS= read -r pattern; do
  [[ -z "$pattern" ]] && continue
  if hits="$(grep -E -- "$pattern" "$out")"; then
    echo "leaked /${pattern}/: ${hits//$'\n'/ | }"
    bad=1
  fi
done <"$forbidden"
[[ "$bad" -eq 0 ]] || fail "$(basename "$config") ships what it shouldn't (above)"
echo "gcp pull check: $(wc -l <"$out") of ${total} entries out, all scrubbed"
