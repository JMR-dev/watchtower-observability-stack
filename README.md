# Watchtower Observability Stack

GDPR-minded, multi-tenant observability (metrics, logs, traces) on our own
Kubernetes cluster in Hetzner's Nuremberg location (nbg1): Mimir, Loki, Tempo
and Grafana, reachable only through WireGuard at the private endpoint
**watchtower.jasonmross.dev**.

- **Infrastructure:** Pulumi in Go (`infra/`), state in a Hetzner Object Storage bucket of its own
- **Kubernetes:** three AlmaLinux 10 nodes (control plane, etcd and workloads on each), built by Kubespray from Ansible (`ansible/`)
- **Workloads:** Pulumi in Go again (`infra/apps`): Helm charts plus our own manifests
- **Object storage:** Hetzner Object Storage, nbg1, one bucket and one S3 key per component
- **Log archive:** every container log, every node's journal and the API audit log, kept 90 days in a bucket of their own
- **Access:** WireGuard (wg-easy) on a Hetzner Floating IP that follows the edge pod between nodes
- **DNS:** the Cloud DNS zone `watchtower.jasonmross.dev`, delegated from `jasonmross.dev`
- **CI/CD:** Gitea Actions: `ci.yml` (status checks), `deploy.yml` (deploy on merge to main)

## Repository layout

| Path | Purpose |
|------|---------|
| `infra/cloud/` | Pulumi: Hetzner network, nodes, firewall, Floating IP, buckets; Cloud DNS records; Ansible inventory |
| `infra/apps/` | Pulumi: everything in the cluster (charts in `values/`, Caddyfile and Fluent Bit config in `files/`) |
| `infra/internal/` | Names shared by both stacks, the config reader, the mock runtime the tests use |
| `fipd/` | The Floating IP controller: keeps the VPN address on the edge pod's node |
| `ansible/` | Node baseline roles and the Kubespray playbooks |
| `build/caddy/` | The edge image: Caddy + Coraza WAF + Cloud DNS DNS-01 |
| `scripts/` | Bootstrap, secrets (`secret-names.txt` lists them all), key rotation, image builds, deploy verification, tenant onboarding, GDPR erasure |
| `config/alloy/` | Client-side Alloy config with PII scrubbing |
| `docs/` | Architecture, runbook, secrets, multi-tenancy, GDPR |

## Quick start

The first deploy is in [docs/runbook.md](docs/runbook.md#first-deploy). In short:

```bash
scripts/secret.sh put <id>            # each secret -> Secret Manager + gopass
source scripts/env.sh                 # credentials from gopass
scripts/bootstrap.sh                  # state bucket, DNS zone + delegation, service accounts, secret grants
scripts/rotate-gcp-key.sh deployer    # the deploy's one GCP key -> Gitea
scripts/secret.sh check               # nothing missing
(cd infra && go build -o bin/cloud ./cloud && go build -o bin/apps ./apps)
(cd infra/cloud && pulumi stack init prod --secrets-provider passphrase)
(cd infra/apps && pulumi stack init prod --secrets-provider passphrase)
git push   # via a PR; merging to main runs deploy.yml
```

## Tests

```bash
cd infra && go test -race -coverprofile=cover.out ./... && ../scripts/coverage-gate.sh cover.out
cd fipd  && go test -race -coverprofile=cover.out ./... && ../scripts/coverage-gate.sh cover.out
```

Both modules hold 100% statement coverage; CI fails below it.

```bash
scripts/check-manifests.sh   # needs go, helm, kubectl, kubeconform, etcd, kube-apiserver
```

renders every chart and every object `infra/apps` builds and dry-runs them
against a throwaway kube-apiserver of the cluster's version, as CI's
`manifests` job does.

## Documentation

- [Architecture](docs/architecture.md)
- [Runbook](docs/runbook.md)
- [Required secrets](docs/required-secrets.md)
- [Multi-tenancy](docs/multi-tenancy.md)
- [GDPR compliance](docs/gdpr-compliance.md)

