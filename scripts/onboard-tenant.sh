#!/usr/bin/env bash
# Onboard a tenant: a Grafana org of its own, with Mimir, Loki and Tempo
# datasources that send the tenant's X-Scope-OrgID. Ported from the old
# ansible playbooks/onboard-tenant.yml. Run from a WireGuard peer: Grafana is
# only reachable through the tunnel.
#
#   scripts/onboard-tenant.sh <tenant-slug> "<Tenant Name>"
#
# The admin password comes from GRAFANA_ADMIN_PASSWORD or gopass
# (watchtower/grafana-admin-password). Also add the tenant to
# watchtower:tenants in infra/apps/Pulumi.prod.yaml so the main org gets its
# datasources too.

set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 <tenant-slug> \"<Tenant Name>\"" >&2; exit 1; }
slug="$1" name="$2"
[[ "$slug" =~ ^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$ ]] || { echo "slug: lowercase letters, digits, dashes, at most 40" >&2; exit 1; }

GRAFANA="${GRAFANA_URL:-https://watchtower.jasonmross.dev}"
password="${GRAFANA_ADMIN_PASSWORD:-$(gopass show -o watchtower/grafana-admin-password)}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
umask 077
# Credentials go through a netrc file, not the command line.
printf 'machine %s login admin password %s\n' "$(sed -E 's|https?://([^/:]+).*|\1|' <<<"$GRAFANA")" "$password" >"$work/netrc"
unset password

api() { # method path [json]
  curl -fsS --netrc-file "$work/netrc" -X "$1" -H 'Content-Type: application/json' \
    ${3:+--data "$3"} "${GRAFANA}$2"
}

echo "==> Grafana org ${name}"
api POST /api/orgs "$(jq -n --arg n "$name" '{name: $n}')" >/dev/null 2>&1 || true
org_id="$(api GET "/api/orgs/name/$(jq -rn --arg n "$name" '$n|@uri')" | jq -r .id)"

echo "==> Datasources in org ${org_id}"
datasource() { # name type url
  jq -n --arg n "$1" --arg t "$2" --arg u "$3" --arg s "$slug" '{
    name: $n, type: $t, access: "proxy", url: $u,
    jsonData: {httpHeaderName1: "X-Scope-OrgID"},
    secureJsonData: {httpHeaderValue1: $s}
  }'
}
for ds in \
  "Mimir|prometheus|http://mimir.watchtower.svc.cluster.local:8080/prometheus" \
  "Loki|loki|http://loki-query-frontend.watchtower.svc.cluster.local:3100" \
  "Tempo|tempo|http://tempo.watchtower.svc.cluster.local:3200"; do
  IFS='|' read -r n t u <<<"$ds"
  curl -fsS --netrc-file "$work/netrc" -X POST -H 'Content-Type: application/json' \
    -H "X-Grafana-Org-Id: ${org_id}" --data "$(datasource "$n" "$t" "$u")" \
    "${GRAFANA}/api/datasources" >/dev/null 2>&1 || echo "    ${n}: already exists"
done
echo "Done: org ${org_id} (${name}), tenant ${slug}."
