# GDPR Compliance

This stack processes telemetry that is **likely to contain personal data**
(IPs, user IDs, request bodies, emails). Compute, telemetry storage, the log
archive and the infrastructure state are all with Hetzner in Nuremberg,
Germany, so personal data stays in the EU.

## Roles

- **Data Controller:** the operator deploying this stack.
- **Data Processor (infrastructure):** Hetzner Online GmbH (DE): servers,
  volumes, Object Storage.
- **Sub-processors:**
  - Google holds the two DNS records of `watchtower.jasonmross.dev` (Cloud
    DNS), the stack's credentials (Secret Manager, europe-west3) and our two
    container images (Artifact Registry, europe-west3). No telemetry, no
    personal data.
  - Let's Encrypt issues the TLS certificate (the domain name only).

## Legal basis (Art. 6)

Document the basis for each tenant (per-tenant section to be filled in).
Typical bases:

- **Art. 6(1)(f)** legitimate interest — operational logging.
- **Art. 6(1)(b)** contract performance — telemetry necessary to deliver a service.

## Required documents

| Document | Status | Notes |
|----------|--------|-------|
| Data Processing Agreement with Hetzner | sign in the Console | Art. 28 |
| Record of Processing Activities (RoPA) | template below | Art. 30 |
| Data Protection Impact Assessment (DPIA) | required | Art. 35 — high-risk processing |
| Breach response runbook | below and `docs/runbook.md` | Art. 33/34 |

## Data residency

| Data | Where |
|---|---|
| Telemetry (Loki, Mimir, Tempo buckets) | Hetzner Object Storage, nbg1 |
| WALs, Kafka's log (24 h of traces), Postgres (Grafana's database), wg-easy's database | Hetzner Volumes, fsn1 (LUKS) |
| Log archive (container logs, journals, audit logs) | Hetzner Object Storage, nbg1 |
| Backups of Grafana's database | Hetzner Object Storage, nbg1 |
| Backup and host-health alerts | Healthchecks.io (no personal data: host and service names, disk use, the backup run's own log) |
| Pulumi state | Hetzner Object Storage, nbg1 |
| DNS records | Google Cloud DNS (global; no personal data) |
| Credentials (API tokens, keys, passwords) | Google Secret Manager, payloads replicated to europe-west3 only (no personal data) |
| Our container images (Caddy, Patroni) | Google Artifact Registry, europe-west3 (no personal data) |

## Retention register

| Data | Application retention | Bucket lifecycle (safety net) | Erasure window |
|---------|----------------------|------------------|--------------------------|
| Logs (Loki) | 30 days (compactor) | 60 days | 30 days, or hours via the delete API |
| Metrics (Mimir) | 90 days (compactor) | 180 days | 90 days |
| Traces (Tempo) | 30 days (backend scheduler) | 60 days | 30 days |
| Log archive: container logs, host journals, audit logs | — | 90 days | 90 days |
| Backups of Grafana's database (users, orgs, dashboards, alert rules) | — | 90 days | 90 days |
| Traces in Kafka (Tempo's ingest path) | 24 hours (topic retention) | — | 24 hours |
| GDPR erasure records (`gdpr-audit/`) | kept | none | — (evidence of erasure; no telemetry) |

Application retention is the erasure mechanism; bucket lifecycle rules
(Hetzner Object Storage supports them) are a safety net behind it.

The **log archive** holds the stack's own logs: Caddy's access log and
Coraza's audit log (client tunnel addresses, request paths), Grafana's log
(user names), host journals (SSH source addresses) and the hosts' audit
logs. Tenant telemetry does not go there, only to Loki, Mimir and Tempo. The
servers' S3 key can only write to the archive, so a compromised host cannot
read or erase it; the 90-day lifecycle is its erasure.

The **Postgres backups** are nightly dumps of Grafana's database: its
users' names, email addresses and logins, tenant orgs, dashboards and alert
rules. A user deleted in Grafana stays in the earlier dumps until they
expire. As with the archive, the servers' key can only add dumps, and the
90-day lifecycle is the erasure.

## PII minimization

### Collector-side scrubbing

Clients run Grafana Alloy with the redaction pipeline in
`config/alloy/config.alloy.example`:

- IPv4 / IPv6 addresses → `[REDACTED-IP*]`
- Email addresses → `[REDACTED-EMAIL]`
- JWT tokens → `[REDACTED-JWT]`
- Bearer tokens in `Authorization` headers → `[REDACTED-TOKEN]`
- Card numbers (PAN, 13–19 digits) → `[REDACTED-PAN]`
- UUIDs → `[REDACTED-UUID]`
- Lines containing `password=`, `ssn=`, `cvv=`, `cvc=` → **dropped**

### OTLP attribute scrubbing

| Attribute | Action |
|-----------|--------|
| `enduser.id` | hashed (correlatable but not reversible) |
| `user.email` | deleted |
| `client.address` | deleted |
| `http.request.header.authorization` | deleted |
| `http.request.header.cookie` | deleted |
| `http.request.body` | deleted |

### Label / cardinality discipline

Mimir and Tempo do **not** support per-record deletion. **No PII may ever
appear in metric labels or trace resource attributes.** Use opaque
identifiers (hashed at the collector), never emails, names or phone numbers.

## Right to erasure (Art. 17)

| Data | Mechanism | Time to effect |
|---|---|---|
| Logs | Loki delete API: `scripts/gdpr-purge.sh` | hours (2 h compactor delay) |
| Metrics | Retention only — short window + label discipline | ≤ 90 days |
| Traces | Retention only | ≤ 30 days |
| Log archive | Lifecycle only | ≤ 90 days |
| Grafana users | Delete the user in Grafana; the database backups expire by lifecycle | at once in Grafana; ≤ 90 days in backups |

Each erasure request is recorded in the log archive under `gdpr-audit/`
(kept indefinitely, writable only with the admin key). Notify the data
subject within one month (Art. 12(3)).

## Encryption

| Layer | Mechanism |
|-------|-----------|
| Client → stack | WireGuard (ChaCha20-Poly1305), then TLS to Caddy |
| Host ↔ host (Caddy to the backends, replication, Kafka, Postgres, etcd) | WireGuard mesh (wg1) over the private network |
| Container ↔ container on one host | None: the traffic never leaves the host |
| Stack → Object Storage | TLS |
| Volumes (WALs, Kafka, Postgres) | LUKS2 |
| Secrets on the hosts | podman secrets, readable by root only; never in unit files or container environment listings |
| Object Storage at rest | Hetzner's server-side encryption |
| Secrets | None in the repo; Google Secret Manager (encrypted at rest), gopass locally |

## Access control & audit

- WireGuard: one peer per client host, managed in wg-easy; revoked at once
  by disabling the peer.
- Hetzner Cloud Firewalls, mirrored on every host by an nftables ruleset:
  SSH from administrator and CI addresses only; WireGuard on the proxy only.
- SSH: keys only, pinned host keys, fail2ban (sshd + recidive).
- Between hosts: only the mesh; Kafka, etcd and Postgres reachable from the
  data nodes alone, the proxy only to the ports Caddy proxies to.
- Containers: non-root where the image allows, read-only roots, capabilities
  dropped; SELinux confinement for all but wg-easy and Fluent Bit.
- Object Storage: an admin key (Pulumi, operators) and one key for the
  servers, fenced by bucket policies: it can't read Pulumi state and can only
  write to the log archive.
- Grafana: org per tenant; login required; anonymous access off. (Grafana's
  `[auditing]` is an Enterprise feature; user activity appears in Grafana's
  own log, which the log archive keeps.)
- The hosts' audit logs (logins, sudo, SELinux denials), kept in the log
  archive for 90 days.
- Tenant isolation: `X-Scope-OrgID` at Mimir/Loki/Tempo plus Grafana org RBAC.

## Breach response (Art. 33/34)

1. **Detect** — Grafana alerts, the hosts' audit logs, Hetzner abuse notices.
2. **Contain** — revoke the affected WireGuard peer; rotate the affected
   credentials (`docs/runbook.md`, "Credential rotation"); redeploy.
3. **Assess** — which tenant, what data, what window. Use the log archive
   (journals, audit logs, Caddy/Coraza logs).
4. **Notify** — within 72 hours, the supervisory authority competent for the
   controller (for a controller in Bavaria, the **BayLDA**,
   https://www.lda.bayern.de/). If high risk to data subjects, notify them
   directly (Art. 34).
5. **Document** — keep a breach record with the above.

## RoPA template

For each tenant, fill in:

- Name & contact of controller
- Categories of data subjects
- Categories of personal data processed in telemetry
- Recipients (none — internal only)
- Transfers outside the EEA (none)
- Retention periods (per signal — see above)
- Technical & organisational measures (this document)
