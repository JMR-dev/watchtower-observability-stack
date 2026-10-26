#!/usr/bin/env bash
# Checks that agent peers (the services shipping telemetry, in the tunnel's
# agent half; docs/client-telemetry.md) can only write telemetry, so a
# refactor can't quietly hand them SSH, the query APIs or Loki's delete API.
# CI runs both checks on the configs rendered from the sample inventory:
#
#   scripts/check-agent-gating.sh nft <rendered watchtower.nft of the proxy>
#       Right after the established, loopback and invalid rules, agents jump
#       to a chain of their own, which accepts only the ingest listeners and
#       drops the rest, so no later rule can admit them.
#   caddy adapt ... | scripts/check-agent-gating.sh caddy
#       Each site's first routes refuse agents (403), except on the ingest
#       paths below, where they overwrite their tenant header; only the WAF
#       may come before.
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
    # A chain's rules, without comments and blank lines.
    rules() { sed -n "/^    chain $1 {\$/,/^    }\$/p" "$nft" | sed -e '1d;$d' -e 's/^ *//' -e '/^#/d' -e '/^$/d'; }
    # Agents jump to their own chain before anything could admit them: only
    # these come first.
    expected_head=$'type filter hook input priority filter; policy drop;\nct state established,related accept\niif "lo" accept\nct state invalid drop\nip saddr @vpn_agents jump agent_peers'
    [[ "$(rules input | head -n 5)" == "$expected_head" ]] \
      || fail "the input chain doesn't start with the agents' jump: $(rules input | head -n 5 | paste -sd'|')"
    [[ "$(rules input | grep -c '@vpn_agents')" -eq 1 ]] || fail "more than one input rule for agents"
    # Which ends in drop, having let through only the ingest listeners.
    expected_agents=$'iifname "wg0" ip daddr 10.8.0.1 tcp dport { 3100, 8080, 4317, 4318 } accept\nlimit rate 5/minute log prefix "nft-agent-drop: " level info\ncounter drop'
    [[ "$(rules agent_peers)" == "$expected_agents" ]] || fail "chain agent_peers is: $(rules agent_peers | paste -sd'|')"
    echo "agent gating (nft): ok"
    ;;
  caddy)
    jq -e --arg cidr "$agent_cidr" --arg tenant "$tenant" '
      {"3100": ["/loki/api/v1/push", "/otlp/v1/logs"],
       "8080": ["/api/v1/push", "/otlp/v1/metrics"],
       "4318": ["/v1/traces"],
       "4317": ["/opentelemetry.proto.collector.trace.v1.TraceService/Export"]} as $writes
      | def agent: any(.match[]?; .remote_ip.ranges == [$cidr]);
        def deny: agent and .handle == [{handler: "static_response", status_code: 403}];
        def header: agent and .handle == [{handler: "headers", request: {set: {"X-Scope-Orgid": [$tenant]}}}];
        def waf: .match == null and (.handle | length) == 1 and .handle[0].handler == "waf";
      [.apps.http.servers[]
       | (.listen[0] | split(":") | last) as $port
       | ((.routes | length) == 1 and (.routes[0].handle | length) == 1
          and .routes[0].handle[0].handler == "subroute") as $shape
       | [.routes[0].handle[0].routes[]?] as $routes
       | [range($routes | length) | select($routes[.] | deny)] as $denies
       | ($denies[0] // 0) as $d
       | {port: $port,
          ok: ($shape and ($denies | length) == 1
               # Before the 403, only the tenant header and the WAF: nothing
               # that could answer or proxy an agent first.
               and all($routes[:$d][]; header or waf)
               and ($routes[$d].match | length) == 1
               and (if $writes[$port]
                    then $routes[$d].match[0].not == [{path: $writes[$port]}] and any($routes[:$d][]; header)
                    else ($routes[$d].match[0] | keys) == ["remote_ip"] and all($routes[:$d][]; header | not) end))}]
      | if length != 7 then error("\(length) sites, expected 7")
        elif all(.ok) then true
        else error("sites not gated: \(map(select(.ok | not) | .port))") end' >/dev/null \
      || fail "the adapted Caddyfile doesn't hold agents to writes"
    echo "agent gating (caddy): ok"
    ;;
  *) echo "usage: $0 nft <watchtower.nft> | caddy (adapted JSON on stdin)" >&2; exit 1 ;;
esac
