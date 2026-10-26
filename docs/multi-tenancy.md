# Multi-tenancy

Several teams or projects share the same Mimir, Loki, Tempo and Grafana.
Tenant isolation is enforced at two layers:

1. **Storage** — Mimir, Loki and Tempo route every read and write by the
   `X-Scope-OrgID` header. Each tenant has a unique slug.
2. **Grafana** — the main org has one datasource set per tenant
   (`watchtower_tenants` in `ansible/inventory/group_vars/all/tenants.yml`), and
   `scripts/onboard-tenant.sh` gives a tenant an org of its own whose
   datasources send only its header.

## Tenant slug rules

- Lowercase ASCII letters, digits and dashes; starts and ends with a letter
  or digit.
- At most 40 characters, unique.
- Examples: `team-alpha`, `web-prod`, `customer-acme`.

`watchtower-smoke` is reserved: `deploy.yml` pushes its verification line
there.

## The shared tenant and agent peers

Our own services (Gitea, Vaultwarden, SilverBullet, the blog, the bastion)
share one tenant, `jasonmross` (docs/client-telemetry.md). Each ships as an
**agent peer**, in the tunnel's upper half, 10.8.0.128/25:

- nftables lets agents reach only Caddy's ingest listeners;
- Caddy lets them use only the write paths (Loki and Mimir push and OTLP,
  Tempo OTLP), overwrites their `X-Scope-OrgID` with `jasonmross`, and
  answers anything else with 403. So an agent can't read, query, delete, or
  write to another tenant.

One tenant is one budget: its Mimir limits (`mimir_limits` in
`tenants.yml`) are sized for all of them together.

**Accepted risk:** inside the shared tenant, labels are what tell services
apart, and any agent can write any label. A compromised blog VM could write
lines or series labelled `host="vault-production"`, and so keep that host's
silence alert quiet. Forcing the tenant doesn't stop that; it keeps a
compromised agent from reading or erasing anything.

## Onboarding

1. Add the tenant (`slug`, `org_name`) to `watchtower_tenants` in
   `ansible/inventory/group_vars/all/tenants.yml` and merge (the main org's
   datasources).
2. From a WireGuard peer:
   ```bash
   scripts/onboard-tenant.sh team-alpha 'Team Alpha'
   ```
   This creates the Grafana org "Team Alpha" with Mimir, Loki and Tempo
   datasources that send `X-Scope-OrgID: team-alpha`. The three Grafanas
   share one database, so one call reaches all of them.
3. Give the tenant's hosts a way in. A peer made in the wg-easy UI is an
   **admin** peer: it can query and delete every tenant's data, so make one
   only for people you trust with all of it. Write-only agent peers exist
   only for `jasonmross` today; another tenant's would need an agent range
   and a forced tenant of its own in the firewall and Caddy.

## Client endpoints

All on `watchtower.jasonmross.dev`, TLS, from a WireGuard peer only. Agent
peers get the write endpoints and nothing else (no Grafana):

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

`config/alloy/config.alloy.example` is the full client config, with the
scrubbing every client needs.

## Offboarding

1. Erase the tenant's logs:
   `scripts/gdpr-purge.sh team-alpha '{job=~".+"}' 2020-01-01T00:00:00Z`
2. Revoke the tenant's WireGuard peers in wg-easy and stop their Alloy.
3. Delete the tenant's Grafana org (Grafana API or UI), and remove it from
   `watchtower_tenants`.
4. Mimir and Tempo have no per-tenant delete: their data ages out after 90
   and 30 days.

## Per-tenant overrides

All through the roles and a deploy:

- **Mimir**: a tenant's `mimir_limits` in `tenants.yml`, rendered into
  `ansible/roles/mimir/templates/runtime.yaml.j2`, which Mimir rereads
  without a restart.
- **Loki**: `limits_config` in `ansible/roles/loki/templates/loki.yaml.j2`,
  the same for every tenant (4 MB/s, 5000 streams); for one tenant, add a
  `runtime_config` file the same way Mimir's is done.
- **Tempo**: `overrides.defaults` in
  `ansible/roles/tempo/templates/tempo.yaml.j2`, the same for every tenant
  (5 MB/s; 10k span-metrics series).
