# Multi-tenancy

Several teams or projects share the same Mimir, Loki, Tempo and Grafana.
Tenant isolation is enforced at two layers:

1. **Storage** — Mimir, Loki and Tempo route every read and write by the
   `X-Scope-OrgID` header. Each tenant has a unique slug.
2. **Grafana** — the main org has one datasource set per tenant
   (`watchtower:tenants` in `infra/apps/Pulumi.prod.yaml`), and
   `scripts/onboard-tenant.sh` gives a tenant an org of its own whose
   datasources send only its header.

## Tenant slug rules

- Lowercase ASCII letters, digits and dashes; starts and ends with a letter
  or digit.
- At most 40 characters, unique.
- Examples: `team-alpha`, `web-prod`, `customer-acme`.

`watchtower-smoke` is reserved: `deploy.yml` pushes its verification line
there.

## Onboarding

1. Add the tenant to `watchtower:tenants` in `infra/apps/Pulumi.prod.yaml`
   and merge (the main org's datasources).
2. From a WireGuard peer:
   ```bash
   scripts/onboard-tenant.sh team-alpha 'Team Alpha'
   ```
   This creates the Grafana org "Team Alpha" with Mimir, Loki and Tempo
   datasources that send `X-Scope-OrgID: team-alpha`.
3. Add a WireGuard peer for each of the tenant's hosts (wg-easy UI) and hand
   over `config/alloy/config.alloy.example` with `TENANT_SLUG` replaced.

## Client endpoints

All on `watchtower.jasonmross.dev`, TLS, from a WireGuard peer only:

| Signal | Endpoint |
|---|---|
| Logs (Loki push) | `https://watchtower.jasonmross.dev:3100/loki/api/v1/push` |
| Logs (OTLP) | `https://watchtower.jasonmross.dev:3100/otlp/v1/logs` |
| Metrics (remote_write) | `https://watchtower.jasonmross.dev:8080/api/v1/push` |
| Metrics (OTLP) | `https://watchtower.jasonmross.dev:8080/otlp/v1/metrics` |
| Traces (OTLP gRPC) | `watchtower.jasonmross.dev:4317` |
| Traces (OTLP HTTP) | `https://watchtower.jasonmross.dev:4318/v1/traces` |
| Grafana | `https://watchtower.jasonmross.dev/` |

```alloy
loki.write "default" {
  endpoint {
    url     = "https://watchtower.jasonmross.dev:3100/loki/api/v1/push"
    headers = { "X-Scope-OrgID" = "team-alpha" }
  }
}
```

## Offboarding

1. Erase the tenant's logs:
   `scripts/gdpr-purge.sh team-alpha '{job=~".+"}' 2020-01-01T00:00:00Z`
2. Revoke the tenant's WireGuard peers in wg-easy and stop their Alloy.
3. Delete the tenant's Grafana org (Grafana API or UI), and remove it from
   `watchtower:tenants`.
4. Mimir and Tempo have no per-tenant delete: their data ages out after 90
   and 30 days.

## Per-tenant overrides

- **Mimir**: the `runtime.yaml` key of the `mimir-config` ConfigMap
  (`infra/apps/mimir.go`) is hot-reloaded; add `overrides: {<tenant>: {...}}`.
- **Loki**: `loki.runtimeConfig` in `infra/apps/values/loki.yaml`.
- **Tempo**: `tempo.per_tenant_overrides` in `infra/apps/values/tempo.yaml`.
