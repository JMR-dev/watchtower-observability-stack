#!/usr/bin/env bash
# Prove a deploy worked; the hosts job's last step. Fails unless:
#   1. Grafana, Loki, Mimir and Tempo answer through Caddy on the tunnel
#      address, over TLS with a valid certificate for the domain;
#   2. a log line pushed through Caddy comes back from a Loki query;
#   3. an OTLP span pushed through Caddy comes back from Tempo;
#   4. the proxy runs the Caddy image this deploy built (by digest);
#   5. the clusters are whole: Loki's and Mimir's ingester rings have every
#      node ACTIVE, Kafka has no under-replicated partition, Patroni has a
#      leader and every replica streaming;
#   6. Fluent Bit has written today's container logs to the archive;
#   7. the nightly backup of Grafana's database, run now on every node, puts
#      a new dump in Object Storage (and pings its Healthchecks.io check);
#   8. every host passes its own health check (roles/health), the one its
#      Healthchecks.io check hears from every 5 minutes.
#
#   scripts/verify.sh <caddy-image-digest> <logs-archive-bucket>
#
# Runs from the deploy runner over SSH, with the inventory and pinned host
# keys the job wrote (ansible/inventory/{hosts.yml,known_hosts}) and the key
# in ANSIBLE_PRIVATE_KEY_FILE: to the proxy on its public address, to the
# nodes on their private ones through the proxy. From a WireGuard peer, set
# WATCHTOWER_SSH_VIA=vpn to reach the proxy on the tunnel address instead.
# The checks through Caddy run on the proxy itself, against 10.8.0.1, so
# they cover TLS, Caddy's routing and every backend without a VPN peer.
# Needs: ssh, jq, aws (admin S3 key in AWS_*).

set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 <caddy-image-digest> <logs-archive-bucket>" >&2; exit 1; }
want_digest="$1" archive="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
inv="${repo_root}/ansible/inventory/hosts.yml"
known="${repo_root}/ansible/inventory/known_hosts"

log() { printf '==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

var() { jq -r ".all.vars.$1" "$inv"; }
host() { jq -r ".all.children.$1.hosts | to_entries[$2].value.$3" "$inv"; }
domain="$(var watchtower_domain)"
tunnel="$(var watchtower_tunnel_ip)"
s3="https://$(var watchtower_s3_endpoint)"
region="$(var watchtower_s3_region)"
proxy_ip="$(host proxy 0 public_ip)"
[[ "${WATCHTOWER_SSH_VIA:-public}" == vpn ]] && proxy_ip="$tunnel"
node_ip="$(host nodes 0 private_ip)"
node_mesh="$(host nodes 0 mesh_ip)"
nodes="$(jq '.all.children.nodes.hosts | length' "$inv")"

ssh_opts=(-i "${ANSIBLE_PRIVATE_KEY_FILE:?}" -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known")
# The callers' arguments are the remote command, expanded here on purpose.
# shellcheck disable=SC2029
on() { # address command...: run as root on the proxy, or on a node (its private address) through the proxy
  local addr=$1
  shift
  if [[ "$addr" == "$proxy_ip" ]]; then
    ssh "${ssh_opts[@]}" "root@${addr}" "$@"
  else
    ssh "${ssh_opts[@]}" -o ProxyCommand="ssh $(printf '%q ' "${ssh_opts[@]}")-W %h:%p root@${proxy_ip}" "root@${addr}" "$@"
  fi
}
# edge <port> <curl args...>: a request to the domain through Caddy, from the
# proxy. --resolve pins the name to the tunnel address; TLS is verified.
edge() {
  local port=$1
  shift
  on "$proxy_ip" curl -fsS --max-time 20 --resolve "${domain}:${port}:${tunnel}" "$@"
}
retry() { # tries delay command...: until it succeeds
  local tries=$1 delay=$2 i
  shift 2
  for ((i = 1; i <= tries; i++)); do
    "$@" >/dev/null 2>&1 && return 0
    sleep "$delay"
  done
  return 1
}

# ---------------------------------------------------------------------------
log "1/8 every endpoint through Caddy, over TLS"
# The first deploy waits on the certificate (DNS-01 propagation).
for check in "443 /api/health Grafana" "3100 /ready Loki" "8080 /ready Mimir" "3200 /ready Tempo"; do
  read -r port path name <<<"$check"
  retry 40 15 edge "$port" "https://${domain}:${port}${path}" || fail "${name} not ready through Caddy on :${port}"
  echo "    ${name} ready"
done

# ---------------------------------------------------------------------------
log "2/8 end-to-end log push and query"
marker="deploy-verify-${GITHUB_SHA:-local}-$(date +%s)"
now_ns="$(date +%s%N)"
push="$(jq -cn --arg ts "$now_ns" --arg line "$marker" \
  '{streams: [{stream: {job: "deploy-verify"}, values: [[$ts, $line]]}]}')"
edge 3100 -X POST -H 'Content-Type: application/json' -H 'X-Scope-OrgID: watchtower-smoke' \
  --data "$push" "https://${domain}:3100/loki/api/v1/push" >/dev/null || fail "Loki rejected the push"
loki_found() {
  edge 3100 -G -H 'X-Scope-OrgID: watchtower-smoke' "https://${domain}:3100/loki/api/v1/query_range" \
    --data-urlencode "query={job=\"deploy-verify\"} |= \"${marker}\"" \
    --data-urlencode "start=$((now_ns - 60000000000))" | jq -e '.data.result | length > 0'
}
retry 24 5 loki_found || fail "the pushed log line never came back from a query"
echo "    pushed and read back ${marker}"

# ---------------------------------------------------------------------------
log "3/8 end-to-end trace push and query"
trace_id="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
span_id="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
span="$(jq -cn --arg t "$trace_id" --arg s "$span_id" --arg now "$now_ns" '{resourceSpans: [{
  resource: {attributes: [{key: "service.name", value: {stringValue: "deploy-verify"}}]},
  scopeSpans: [{spans: [{traceId: $t, spanId: $s, name: "verify", kind: 1,
    startTimeUnixNano: $now, endTimeUnixNano: (($now | tonumber) + 1000000 | tostring)}]}]}]}')"
edge 4318 -X POST -H 'Content-Type: application/json' -H 'X-Scope-OrgID: watchtower-smoke' \
  --data "$span" "https://${domain}:4318/v1/traces" >/dev/null || fail "Tempo rejected the span"
retry 24 5 edge 3200 -H 'X-Scope-OrgID: watchtower-smoke' "https://${domain}:3200/api/v2/traces/${trace_id}" \
  || fail "trace ${trace_id} never came back from Tempo"
echo "    pushed and read back trace ${trace_id}"

# ---------------------------------------------------------------------------
log "4/8 Caddy image"
running="$(on "$proxy_ip" podman inspect caddy --format '{{.ImageDigest}}')"
[[ "$running" == "$want_digest" ]] || fail "the proxy runs ${running}, not ${want_digest}"
echo "    caddy is ${want_digest}"

# ---------------------------------------------------------------------------
log "5/8 the clusters are whole"
active() { # url: ACTIVE members of a dskit ring
  on "$node_ip" curl -fsS --max-time 10 -H 'Accept: application/json' "$1" \
    | jq '[.shards[] | select(.state == "ACTIVE")] | length'
}
[[ "$(active "http://${node_mesh}:3100/ring")" == "$nodes" ]] || fail "Loki's ingester ring is missing a node"
[[ "$(active "http://${node_mesh}:8080/ingester/ring")" == "$nodes" ]] || fail "Mimir's ingester ring is missing a node"
under="$(on "$node_ip" podman exec kafka /opt/kafka/bin/kafka-topics.sh \
  "--bootstrap-server=${node_mesh}:9092" --describe --under-replicated-partitions)"
[[ -z "$under" ]] || fail "Kafka has under-replicated partitions: ${under}"
cluster="$(on "$node_ip" curl -fsS --max-time 10 "http://${node_mesh}:8008/cluster")"
jq -e --argjson n "$nodes" '([.members[] | select(.role == "leader")] | length) == 1
  and ([.members[] | select(.state == "running" or .state == "streaming")] | length) == $n' \
  <<<"$cluster" >/dev/null || fail "Patroni is not a leader with every replica streaming: ${cluster}"
echo "    rings ACTIVE on ${nodes} nodes, Kafka fully replicated, Patroni healthy"

# ---------------------------------------------------------------------------
log "6/8 log archive"
prefix="containers/$(date -u +%Y/%m/%d)/"
archived() { aws --endpoint-url "$s3" --region "$region" s3 ls "s3://${archive}/${prefix}" --recursive | grep -q .; }
# Fluent Bit uploads every 5 minutes (upload_timeout); wait up to 8.
retry 16 30 archived || fail "nothing under s3://${archive}/${prefix} yet"
echo "    container logs are being archived"

# ---------------------------------------------------------------------------
log "7/8 Grafana database backup"
backups="$(var 'watchtower_buckets["postgres-backups"]')"
backup_prefix="$(var watchtower_postgres_backup_prefix)"
# Keys carry a UTC timestamp, so anything after this one is from this run.
since="${backup_prefix}grafana-$(date -u -d '-2 min' +%Y%m%dT%H%M%SZ)"
# Only the Postgres leader dumps; on the others the run checks a leader exists.
for ((i = 0; i < nodes; i++)); do
  on "$(host nodes "$i" private_ip)" systemctl start watchtower-pg-backup.service ||
    fail "the backup failed on node $((i + 1)): journalctl -u watchtower-pg-backup there"
done
newest="$(aws --endpoint-url "$s3" --region "$region" s3api list-objects-v2 --bucket "$backups" \
  --prefix "$backup_prefix" --start-after "$since" --query 'Contents[-1].[Key,Size]' --output text)"
[[ -n "$newest" && "$newest" != None ]] || fail "no new dump under s3://${backups}/${backup_prefix}"
echo "    $(cut -f1 <<<"$newest") ($(cut -f2 <<<"$newest") bytes)"

# ---------------------------------------------------------------------------
log "8/8 every host's own health check"
for ip in "$proxy_ip" $(jq -r '.all.children.nodes.hosts[].private_ip' "$inv"); do
  problems="$(on "$ip" watchtower-health check)" || fail "${ip}: ${problems}"
done
echo "    the proxy and ${nodes} nodes are healthy"

log "verified"
