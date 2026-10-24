#!/usr/bin/env bash
# Prove a deploy worked; deploy.yml's last job. Fails unless:
#   1. every workload finished rolling out;
#   2. Loki, Mimir, Tempo and Grafana report ready;
#   3. a log line pushed through Loki's distributor can be queried back;
#   4. the edge pod runs the Caddy image this deploy built (by digest);
#   5. the VPN Floating IP is routed to the edge pod's node;
#   6. Fluent Bit has written today's container logs to the archive.
#
#   scripts/verify.sh <caddy-image-digest> <logs-archive-bucket>
#
# Needs: kubectl (KUBECONFIG), curl, jq, aws (admin S3 key in AWS_*),
# HCLOUD_TOKEN.

set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 <caddy-image-digest> <logs-archive-bucket>" >&2; exit 1; }
want_digest="$1" archive="$2"
S3_ENDPOINT="https://nbg1.your-objectstorage.com"

log() { printf '==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

work="$(mktemp -d)"
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
log "1/6 rollouts"
for ns in kube-system watchtower watchtower-edge watchtower-fip logging; do
  for kind in deployment statefulset daemonset; do
    while read -r name; do
      [[ -n "$name" ]] || continue
      kubectl -n "$ns" rollout status "$kind/$name" --timeout=15m
    done < <(kubectl -n "$ns" get "$kind" -o name 2>/dev/null | sed 's|.*/||')
  done
done

# ---------------------------------------------------------------------------
log "2/6 readiness"
ready() { # namespace service port path
  for _ in $(seq 1 30); do
    if kubectl get --raw "/api/v1/namespaces/$1/services/http:$2:$3/proxy$4" >/dev/null 2>&1; then
      echo "    $2 ready"
      return 0
    fi
    sleep 10
  done
  fail "$2 not ready after 5 minutes"
}
ready watchtower loki-query-frontend 3100 /ready
ready watchtower loki-distributor 3100 /ready
ready watchtower mimir 8080 /ready
ready watchtower tempo 3200 /ready
ready watchtower grafana 80 /api/health

# ---------------------------------------------------------------------------
log "3/6 end-to-end log push and query"
forward() { # service local-port remote-port
  kubectl -n watchtower port-forward "svc/$1" "$2:$3" >"$work/pf-$1.log" 2>&1 &
  pids+=("$!")
}
forward loki-distributor 13100 3100
forward loki-query-frontend 13101 3100
sleep 3
marker="deploy-verify-${GITHUB_SHA:-local}-$(date +%s)"
now_ns="$(date +%s%N)"
jq -n --arg ts "$now_ns" --arg line "$marker" \
  '{streams: [{stream: {job: "deploy-verify"}, values: [[$ts, $line]]}]}' >"$work/push.json"
curl -fsS -X POST -H 'Content-Type: application/json' -H 'X-Scope-OrgID: watchtower-smoke' \
  --data @"$work/push.json" http://127.0.0.1:13100/loki/api/v1/push \
  || fail "push to the distributor was rejected"
found=""
for _ in $(seq 1 24); do
  if curl -fsS -G -H 'X-Scope-OrgID: watchtower-smoke' http://127.0.0.1:13101/loki/api/v1/query_range \
      --data-urlencode "query={job=\"deploy-verify\"} |= \"${marker}\"" \
      --data-urlencode "start=$((now_ns - 60000000000))" \
      | jq -e '.data.result | length > 0' >/dev/null 2>&1; then
    found=yes
    break
  fi
  sleep 5
done
[[ -n "$found" ]] || fail "pushed log line never came back from a query"
echo "    pushed and read back ${marker}"

# ---------------------------------------------------------------------------
log "4/6 edge image"
edge_pod="$(kubectl -n watchtower-edge get pod -l app.kubernetes.io/name=edge \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')"
[[ -n "$edge_pod" ]] || fail "no running edge pod"
image_id="$(kubectl -n watchtower-edge get pod "$edge_pod" \
  -o jsonpath='{.status.containerStatuses[?(@.name=="caddy")].imageID}')"
[[ "$image_id" == *"$want_digest" ]] || fail "edge runs ${image_id}, not ${want_digest}"
echo "    caddy is ${want_digest}"

# ---------------------------------------------------------------------------
log "5/6 floating IP follows the edge pod"
edge_node="$(kubectl -n watchtower-edge get pod "$edge_pod" -o jsonpath='{.spec.nodeName}')"
want_server="$(kubectl get node "$edge_node" -o jsonpath='{.spec.providerID}' | sed 's|^hcloud://||')"
printf 'Authorization: Bearer %s\n' "$HCLOUD_TOKEN" >"$work/hcloud-header"
assigned=""
# fipd reconciles every 10s; give it a minute after the rollout.
for _ in $(seq 1 12); do
  assigned="$(curl -fsS -H @"$work/hcloud-header" \
    'https://api.hetzner.cloud/v1/floating_ips?label_selector=role%3Dwatchtower-vpn' \
    | jq -r '.floating_ips[0].server // empty')"
  [[ "$assigned" == "$want_server" ]] && break
  sleep 5
done
[[ "$assigned" == "$want_server" ]] || fail "floating IP is on server ${assigned:-none}, edge runs on ${edge_node} (${want_server})"
echo "    floating IP on ${edge_node}"

# ---------------------------------------------------------------------------
log "6/6 log archive"
prefix="containers/$(date -u +%Y/%m/%d)/"
archived=""
# Fluent Bit uploads every 5 minutes (upload_timeout); wait up to 8.
for _ in $(seq 1 16); do
  if aws --endpoint-url "$S3_ENDPOINT" --region nbg1 s3 ls "s3://${archive}/${prefix}" --recursive | grep -q .; then
    archived=yes
    break
  fi
  sleep 30
done
[[ -n "$archived" ]] || fail "nothing under s3://${archive}/${prefix} yet"
echo "    container logs are being archived"

log "verified"
