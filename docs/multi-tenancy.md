# Multi-tenancy

This stack is multi-tenant: multiple teams or projects share the same Mimir,
Loki, Tempo, and Grafana instances. Tenant isolation is enforced at two layers:

1. **Storage layer** — Mimir/Loki/Tempo route reads and writes by the
   `X-Scope-OrgID` HTTP header. Each tenant has a unique slug.
2. **Grafana layer** — one Org per tenant. Each Org has its own datasources
   that inject the tenant's `X-Scope-OrgID` automatically.

## Tenant slug rules

- Lowercase ASCII letters, digits, and dashes only.
- Max 40 characters.
- Must be unique across the deployment.
- Examples: `team-alpha`, `web-prod`, `customer-acme`.

## Onboarding

```bash
ansible-playbook ansible/playbooks/onboard-tenant.yml \
  -e tenant_slug=team-alpha \
  -e tenant_name='Team Alpha' \
  -e admin_email=alpha-admin@example.com
```

This creates a Grafana Org named "Team Alpha", switches into it, and
provisions Mimir/Loki/Tempo datasources whose secure HTTP header
`X-Scope-OrgID = team-alpha` is set.

## Client configuration

Clients use Grafana Alloy with the tenant slug embedded:

```alloy
loki.write "default" {
  endpoint {
    url = "http://10.8.0.1:3100/loki/api/v1/push"
    headers = { "X-Scope-OrgID" = "team-alpha" }
  }
}
```

See `config/alloy/config.alloy.example`.

## Offboarding

1. Submit Loki delete requests for the tenant's logs:
   `ansible-playbook playbooks/gdpr-purge.yml -e tenant=team-alpha -e selector='{job=~".+"}' -e start=2020-01-01T00:00:00Z`
2. Stop ingesting (revoke the tenant's WireGuard peer + remove their Alloy
   instance).
3. Delete the Grafana Org via the Grafana API.
4. Wait for retention to lapse on Mimir/Tempo (90/14 days respectively) — they
   have no per-tenant deletion API on this version.

## Per-tenant overrides

Mimir limits, Loki retention, etc. can be customized per tenant via
`runtime.yaml` (Mimir) or `limits_config` overrides (Loki). Add per-tenant
sections under `overrides:` in each config — see upstream docs for the schema.
