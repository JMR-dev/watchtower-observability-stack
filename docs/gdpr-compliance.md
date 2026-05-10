# GDPR Compliance

This stack processes telemetry that is **likely to contain personal data**
(IPs, user IDs, request bodies, emails). The deployment is hosted by Hetzner
in Nuremberg, Germany — all data stays within the EU.

## Roles

- **Data Controller:** the operator deploying this stack.
- **Data Processor (infrastructure):** Hetzner Online GmbH (DE).
- **Sub-processors:** none by default.

## Legal basis (Art. 6)

Document the basis for each tenant under
`docs/gdpr-compliance.md` (per-tenant section to be filled in). Typical bases:

- **Art. 6(1)(f)** legitimate interest — operational logging.
- **Art. 6(1)(b)** contract performance — telemetry necessary to deliver service.

## Required documents

| Document | Status | Notes |
|----------|--------|-------|
| Data Processing Agreement with Hetzner | sign in Cloud Console | required Art. 28 |
| Record of Processing Activities (RoPA) | template below | required Art. 30 |
| Data Protection Impact Assessment (DPIA) | required | Art. 35 — high-risk processing |
| Breach response runbook | `docs/runbook.md` | Art. 33/34 |

## Data residency

All telemetry buckets live in `nbg1` (Hetzner, Nuremberg). The OpenTofu
state lives in Cloudflare R2 — operators must configure R2 to use only EU
jurisdictions (`Jurisdiction: EU`) when creating the state bucket, otherwise
state metadata may be replicated outside the EU.

## Retention register

| Signal  | Application Retention | Bucket Lifecycle | Effective Erasure Window |
|---------|----------------------|------------------|--------------------------|
| Logs    | 30 days (Loki)       | 90 days (S3 lifecycle) | 30 days (compactor) |
| Metrics | 90 days (Mimir)      | 365 days (S3 lifecycle)| 90 days (compactor) |
| Traces  | 14 days (Tempo)      | 30 days (S3 lifecycle) | 14 days (compactor) |

Bucket-level lifecycle is a **safety net** — application-level retention is
the primary erasure mechanism. The wider lifecycle window allows
application-level rollback in case of a misconfiguration.

## PII minimization

### Collector-side scrubbing

Clients run Grafana Alloy with the redaction pipeline at
`config/alloy/config.alloy.example`. Patterns redacted:

- IPv4 / IPv6 addresses → `[REDACTED-IP*]`
- Email addresses → `[REDACTED-EMAIL]`
- JWT tokens → `[REDACTED-JWT]`
- Bearer tokens in `Authorization` headers → `[REDACTED-TOKEN]`
- Card numbers (PAN, 13–19 digits) → `[REDACTED-PAN]`
- UUIDs → `[REDACTED-UUID]`
- Lines containing `password=`, `ssn=`, `cvv=`, `cvc=` → **dropped**

### OTLP attribute scrubbing

The `otelcol.processor.attributes` block hashes/deletes these attributes
before traces reach Tempo:

| Attribute | Action |
|-----------|--------|
| `enduser.id` | hashed (correlatable but not reversible) |
| `user.email` | deleted |
| `client.address` | deleted |
| `http.request.header.authorization` | deleted |
| `http.request.header.cookie` | deleted |
| `http.request.body` | deleted |

### Label / cardinality discipline

Mimir and Tempo do **not** support per-record deletion. To stay compliant,
**no PII may ever appear in metric labels or trace resource attributes**.
Tenants must use opaque identifiers (UUIDs hashed at the collector, opaque
session IDs) — never emails, names, or phone numbers as label values.

## Right to erasure (Art. 17)

| Signal  | Mechanism | RTO |
|---------|-----------|-----|
| Logs    | Loki Delete API via `playbooks/gdpr-purge.yml` | hours |
| Metrics | Retention only — short window + label discipline | ≤90 days |
| Traces  | Retention only — 14-day window | ≤14 days |

Document each erasure in `/var/log/observability/gdpr-audit.log` (the playbook
appends automatically). Notify the data subject within one month per Art. 12(3).

## Encryption

| Layer | Mechanism |
|-------|-----------|
| In transit (client → server) | WireGuard (ChaCha20-Poly1305) |
| In transit (server → S3) | TLS 1.2+ |
| At rest (local WAL/Grafana DB) | LUKS2 |
| At rest (S3) | Hetzner SSE |

## Access control & audit

- WireGuard: each peer has its own key; revoke by removing from `wg0.conf`.
- Host firewall: nftables with default-drop input policy. Service ports are
  bound to `10.8.0.1` (wg0) and unreachable on the public interface. SSH and
  WireGuard are restricted to administrator CIDRs (`admin_allow_ipv4` /
  `admin_allow_ipv6`) and rate-limited at the kernel.
- fail2ban: brute-force defense for SSH (jail `sshd`) plus a `recidive` jail
  that long-bans repeat offenders. Bans are enforced via fail2ban's own
  nftables table (`inet f2b-table`).
- Grafana: `[auditing]` enabled — all dashboard / API actions logged to
  `/var/log/grafana/audit.log` with rotation.
- SSH: ed25519 keys only, root password auth disabled.
- Tenant isolation: enforced by `X-Scope-OrgID` at Mimir/Loki/Tempo plus
  Grafana Org RBAC.

## Breach response (Art. 33/34)

72-hour notification to the **Bayerisches Landesamt für Datenschutzaufsicht
(BayLDA)** — Bavaria's supervisory authority. Procedure documented in
`docs/runbook.md` § Breach Response.

## RoPA template

For each tenant, fill in:

- Name & contact of controller
- Categories of data subjects
- Categories of personal data processed in telemetry
- Recipients (none — internal only)
- Transfers outside EEA (none)
- Retention periods (per signal — see above)
- Technical & organisational measures (this document)
