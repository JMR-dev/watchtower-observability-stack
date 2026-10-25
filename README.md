# Watchtower Observability Stack

GDPR-minded, multi-tenant observability (metrics, logs, traces) in Hetzner's
Falkenstein location (fsn1): Mimir, Loki, Tempo and Grafana as podman
containers on three ARM servers, with their Object Storage alongside,
reachable only through WireGuard at the private endpoint
**watchtower.jasonmross.dev**.

- **Hosts:** three cax31 data nodes and one cax11 proxy, all ARM64, in fsn1; AlmaLinux 10, SELinux enforcing; exactly the account's 26-vCPU cap
- **Infrastructure:** Pulumi in Go (`infra/cloud`), state in a Hetzner Object Storage bucket of its own
- **Install:** Ansible (`ansible/`) puts everything on the hosts as rootful podman quadlets; no Kubernetes
- **High availability:** Loki and Mimir as three monolithic replicas (RF 3); Tempo in microservices mode on a 3-broker Kafka; three Grafanas on Postgres kept highly available by Patroni and etcd. Any one data node can be lost; the proxy is the one single point of failure
- **Network:** a WireGuard mesh between all four hosts carries every byte between them; Caddy on the proxy load-balances each port across the nodes with health checks
- **Object storage:** Hetzner Object Storage, fsn1; two S3 keys (admin, and one for the servers, fenced by bucket policies)
- **Log archive:** every container's log, every host's journal and audit log, kept 90 days in a bucket of their own
- **Backups:** Grafana's database dumped nightly to Object Storage and kept 90 days, with a Healthchecks.io alert the moment a run fails
- **Host health:** every host checks its services, disks and SELinux every 5 minutes and reports to its own Healthchecks.io check, so a lost node is noticed even though users aren't affected
- **Access:** WireGuard (wg-easy) on the proxy; Caddy (with the Coraza WAF) answers only on the tunnel address
- **Images:** our two (Caddy, Patroni) in a private Artifact Registry repo, built natively per architecture, scanned by Trivy
- **DNS:** the Cloud DNS zone `watchtower.jasonmross.dev`, delegated from `jasonmross.dev`
- **CI/CD:** Gitea Actions: `ci.yml` (status checks), `deploy.yml` (deploy on merge to main)

## Repository layout

| Path | Purpose |
|------|---------|
| `infra/cloud/` | Pulumi: Hetzner network, hosts, volumes, firewalls, buckets; Cloud DNS records; the Ansible inventory |
| `infra/internal/` | Shared names, the config reader, Secret Manager reads, the mock runtime the tests use |
| `ansible/` | Everything on the hosts: one role per service, `playbooks/site.yml`, `playbooks/render.yml` |
| `build/caddy/` | The proxy image: Caddy + Coraza WAF + Cloud DNS DNS-01 |
| `build/patroni/` | Patroni + PostgreSQL 18 for the nodes, built with uv |
| `scripts/` | Bootstrap, secrets, Healthchecks.io checks, key rotation, image builds and checks, deploy verification, tenant onboarding, GDPR erasure |
| `config/alloy/` | Client-side Alloy config with PII scrubbing |
| `docs/` | Architecture, runbook, secrets, multi-tenancy, GDPR |

## Quick start

The first deploy is in [docs/runbook.md](docs/runbook.md#first-deploy). In short:

```bash
scripts/secret.sh put <id>            # each secret -> Secret Manager + gopass
source scripts/env.sh                 # credentials from gopass
scripts/bootstrap.sh                  # state bucket, DNS, service accounts, registry, secret grants
scripts/rotate-gcp-key.sh deployer    # the deploy's GCP key -> Gitea (also caddy, pusher, puller)
scripts/secret.sh check               # nothing missing
(cd infra && go build -o bin/cloud ./cloud)
(cd infra/cloud && pulumi stack init prod --secrets-provider passphrase)
git push   # via a PR; merging to main runs deploy.yml
```

## Tests and checks

```bash
cd infra && go test -race -coverprofile=cover.out ./... && ../scripts/coverage-gate.sh cover.out
```

The Go module holds 100% statement coverage; CI fails below it.

```bash
(cd ansible && ansible-playbook -i inventory/hosts.sample.yml playbooks/render.yml)
CONTAINER_RUNTIME=podman scripts/check-configs.sh
```

renders every host's configs from the sample inventory and checks each with
the program that reads it (quadlet, Loki, Mimir, Tempo, Fluent Bit;
shellcheck for the host scripts), as CI's `configs` job does. `scripts/build-image.sh` checks the Caddyfile and
`patroni.yml` with the images it builds.

## Documentation

- [Architecture](docs/architecture.md)
- [Runbook](docs/runbook.md)
- [Required secrets](docs/required-secrets.md)
- [Multi-tenancy](docs/multi-tenancy.md)
- [GDPR compliance](docs/gdpr-compliance.md)
