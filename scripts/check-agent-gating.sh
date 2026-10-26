#!/usr/bin/env bash
# Checks that agent peers (the services shipping telemetry, in the tunnel's
# agent half; docs/client-telemetry.md) can only write telemetry, so a
# refactor can't quietly hand them SSH, the query APIs or Loki's delete API.
# CI runs both checks on the configs rendered from the sample inventory:
#
#   scripts/check-agent-gating.sh nft <rendered watchtower.nft of the proxy>
#       Agents' only accept is the ingest listeners, and their drop comes
#       before any other rule on wg0 (the broad peer accept among them).
#   caddy adapt ... | scripts/check-agent-gating.sh caddy
#       On every site Caddy refuses agents (403) before it proxies, except on
#       the ingest paths below, where it overwrites their tenant header.
#
# The expected ports and paths are spelled out here on purpose: widening
# what agents reach has to change this file too.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sample="${repo_root}/ansible/inventory/hosts.sample.yml"
agent_cidr="$(sed -n 's/^    watchtower_agent_cidr: //p' "$sample")"
tenant="$(sed -n 's/^    watchtower_agent_tenant: //p' "$sample")"
[[ -n "$agent_cidr" && -n "$tenant" ]] || { echo "no agent CIDR or tenant in ${sample}" >&2; exit 1; }

fail() { echo "agent gating: $*" >&2; exit 1; }

case "${1:-}" in
  nft)
    nft="${2:?usage: $0 nft <watchtower.nft>}"
    grep -q "elements = { ${agent_cidr} }" "$nft" || fail "set vpn_agents is not ${agent_cidr}"
    accept="$(grep -n 'ip saddr @vpn_agents .* accept$' "$nft")" || fail "no accept for agents"
    [[ "$(wc -l <<<"$accept")" -eq 1 ]] || fail "more than one accept for agents"
    [[ "$accept" == *"tcp dport { 3100, 8080, 4317, 4318 } accept" ]] || fail "agents accepted on: ${accept#*:}"
    drop="$(grep -n 'iifname "wg0" ip saddr @vpn_agents counter drop$' "$nft" | cut -d: -f1)"
    [[ -n "$drop" ]] || fail "no drop for agents"
    # Every wg0 rule ahead of the drop is one of the agents' own.
    while IFS=: read -r n line; do
      ((n < drop)) || break
      [[ "$line" == *"@vpn_agents"* ]] || fail "line ${n}, ahead of the agents' drop, admits wg0: ${line}"
    done < <(grep -n 'iifname "wg0"' "$nft")
    grep -q 'iifname "wg0" ip daddr .* accept$' "$nft" || fail "no accept for admin peers (did the rules move?)"
    echo "agent gating (nft): ok"
    ;;
  caddy)
    jq -e --arg cidr "$agent_cidr" --arg tenant "$tenant" '
      {"3100": ["/loki/api/v1/push", "/otlp/v1/logs"],
       "8080": ["/api/v1/push", "/otlp/v1/metrics"],
       "4318": ["/v1/traces"],
       "4317": ["/opentelemetry.proto.collector.trace.v1.TraceService/Export"]} as $writes
      | [.apps.http.servers[]
         | (.listen[0] | split(":") | last) as $port
         | [.routes[].handle[] | select(.handler == "subroute") | .routes[]] as $routes
         | ($routes | map(any(.match[]?; .remote_ip.ranges == [$cidr]))) as $agent
         | ($routes | map(any(.handle[]; .handler == "reverse_proxy"))) as $proxies
         | [range($routes | length) | select($agent[.])] as $agent_at
         | [range($routes | length) | select($proxies[.])][0] as $proxy_at
         | [$agent_at[] | $routes[.] | select(.handle[0] == {handler: "static_response", status_code: 403})] as $denies
         | {port: $port,
            ok: ($proxy_at != null and ($agent_at | length) > 0 and ($agent_at | max) < $proxy_at
                 and ($denies | length) == 1
                 and (if $writes[$port]
                      then $denies[0].match[0].not == [{path: $writes[$port]}]
                           and any($agent_at[] | $routes[.];
                                   .handle[0].handler == "headers" and .handle[0].request.set["X-Scope-Orgid"] == [$tenant])
                      else $denies[0].match[0].not == null end))}]
      | if length != 7 then error("\(length) sites, expected 7")
        elif all(.ok) then true
        else error("sites not gated: \(map(select(.ok | not) | .port))") end' >/dev/null \
      || fail "the adapted Caddyfile doesn't hold agents to writes"
    echo "agent gating (caddy): ok"
    ;;
  *) echo "usage: $0 nft <watchtower.nft> | caddy (adapted JSON on stdin)" >&2; exit 1 ;;
esac
