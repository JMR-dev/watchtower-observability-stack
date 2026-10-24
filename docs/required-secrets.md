# Required secrets

Nothing secret is committed in plaintext. There are three places secrets
live:

1. **gopass** (`watchtower/...`), for owner-run commands; `scripts/env.sh`
   exports them.
2. **Gitea Actions repo secrets**, for `deploy.yml`. `ci.yml` uses none.
3. **Pulumi stack config**, encrypted with the passphrase provider and
   committed, for anything the cluster's workloads need.

## Gitea Actions secrets (and their gopass twins)

| Secret | gopass path | Used by | Notes |
|---|---|---|---|
| `HCLOUD_TOKEN` | `watchtower/hcloud-token` | Pulumi `cloud`, `scripts/verify.sh` | Hetzner API, read/write |
| `HCLOUD_CCM_TOKEN` | `watchtower/hcloud-ccm-token` | Kubespray → `kube-system/hcloud` (CCM and hcloud-csi) | Separate token so it can be rotated alone |
| `S3_ADMIN_ACCESS_KEY` | `watchtower/s3-admin-access-key` | Pulumi backend, MinIO provider, `verify.sh` | The only key the state bucket admits |
| `S3_ADMIN_SECRET_KEY` | `watchtower/s3-admin-secret-key` | same | |
| `PULUMI_CONFIG_PASSPHRASE` | `watchtower/pulumi-passphrase` | both stacks | At least 32 random bytes: the repo is mirrored publicly |
| `GCP_DNS_DEPLOYER_KEY` | `watchtower/gcp-dns-deployer-key` | Pulumi `cloud` (DNS records) | JSON key of `watchtower-dns-deployer@watchtower-observe`; `dns.admin` on the one zone; `scripts/rotate-gcp-key.sh deployer` |
| `SSH_PRIVATE_KEY` | `watchtower/ssh-private-key` | Ansible | ed25519; root on the nodes |
| `REGISTRY_TOKEN` | — | image pushes | Gitea token, `write:package` |

## Pulumi stack config

### `infra/cloud` (`Pulumi.prod.yaml`)

| Key | Secret? | Notes |
|---|---|---|
| `watchtower:hetznerProjectId` | no | From the Console URL |
| `watchtower:sshPublicKey` | no | Public half of `SSH_PRIVATE_KEY` |
| `watchtower:adminCidrs`, `ciCidrs`, `wireguardAllowCidrs` | no | Firewall sources |
| `watchtower:bucketPrefix` | no | Must match the apps stack |
| `watchtower:s3AccessKeys.{admin,loki,mimir,tempo,logship}` | **yes** | Access key IDs the bucket policies name |

### `infra/apps` (`Pulumi.prod.yaml`)

| Key | Notes |
|---|---|
| `watchtower:grafanaAdminPassword` | Also in gopass as `watchtower/grafana-admin-password` (onboarding script) |
| `watchtower:wgEasyPassword` | wg-easy's first-start admin password |
| `watchtower:caddyDnsKey` | JSON key of `watchtower-caddy-dns01@`; `scripts/rotate-gcp-key.sh caddy` |
| `watchtower:luksPassphrase` | Encrypts every hcloud-csi volume. **Losing it loses the volumes' data** |
| `watchtower:registryToken` | Gitea token, `read:package`, for image pulls |
| `watchtower:hcloudFipToken` | Hetzner token for fipd only |
| `watchtower:s3Keys.{loki,mimir,tempo,logship}.{accessKey,secretKey}` | One S3 key per component |

`watchtower:caddyImage` and `watchtower:fipdImage` are not secrets and are
not committed: `deploy.yml` sets them to the digests it just built.

## What each S3 key can reach

Bucket policies (Hetzner's `p<project>:<key>` principals) deny every key but
the admin key and the bucket's own:

| Bucket | Admin | loki | mimir | tempo | logship |
|---|---|---|---|---|---|
| `-pulumi-state` | ✓ | | | | |
| `-loki` | ✓ | ✓ | | | |
| `-mimir-blocks`, `-mimir-ruler`, `-mimir-alertmanager` | ✓ | | ✓ | | |
| `-tempo` | ✓ | | | ✓ | |
| `-logs-archive` | ✓ | | | | write only, not `gdpr-audit/` |

A side effect: the Hetzner Console can no longer list these buckets'
objects. Use the admin key with `aws s3`.
