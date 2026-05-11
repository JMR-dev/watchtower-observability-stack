# Watchtower Observability Stack

GDPR-compliant, multi-tenant observability stack (metrics, logs, traces) running on a
single Hetzner CPX42 in Nuremberg (nbg1). Built with Mimir, Loki, Tempo, and Grafana.

- **Infrastructure:** OpenTofu (state in Cloudflare R2)
- **Server config:** Ansible
- **Container runtime:** Podman Quadlets on AlmaLinux 10
- **Object storage:** Hetzner Object Storage (S3-compatible, EU-resident)
- **Access:** WireGuard VPN only — no public service ports

## Quick start

```bash
# 1. Provision infrastructure
cd tofu
cp backend.hcl.example backend.hcl          # set your Cloudflare Account ID
cp terraform.tfvars.example terraform.tfvars # set Hetzner tokens + SSH key
set -a && source .env && set +a             # load R2 credentials into env
tofu init -backend-config=backend.hcl
tofu apply

# 2. Configure server
cd ../ansible
cp inventory/hosts.yml.example inventory/hosts.yml   # set host from tofu output
ansible-playbook -i inventory/hosts.yml playbooks/site.yml --ask-vault-pass

# 3. Onboard your first tenant
ansible-playbook playbooks/onboard-tenant.yml -e tenant_slug=team-alpha
```

## Repository layout

| Path | Purpose |
|------|---------|
| `tofu/`       | OpenTofu infrastructure (Hetzner Cloud + Object Storage, Cloudflare R2 state) |
| `ansible/`    | Server provisioning roles and playbooks |
| `quadlets/`   | Podman Quadlet unit files (deployed by Ansible) |
| `config/`     | Mimir, Loki, Tempo, Grafana configuration templates |
| `wireguard/`  | WireGuard server template (peers vaulted in Ansible) |
| `scripts/`    | Operational scripts (gdpr-purge, onboard-tenant, etc.) |
| `docs/`       | Architecture, GDPR, multi-tenancy, runbook |

## Documentation

- [Architecture](docs/architecture.md)
- [GDPR compliance](docs/gdpr-compliance.md)
- [Multi-tenancy](docs/multi-tenancy.md)
- [Runbook](docs/runbook.md)

## Required secrets

| Secret | Where | Stored as |
|--------|-------|-----------|
| Hetzner Cloud API token | OpenTofu | `terraform.tfvars` (gitignored) |
| Hetzner Object Storage S3 keys | OpenTofu + Ansible | `terraform.tfvars` + Ansible vault |
| Cloudflare R2 access key/secret | OpenTofu backend | env vars `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` |
| WireGuard server private key | Ansible | Ansible vault |
| Grafana admin password | Ansible | Ansible vault |

## License

See [LICENSE](LICENSE).
