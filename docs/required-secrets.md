# Required secrets

Nothing secret is committed, encrypted or not: the repo is mirrored
publicly. Every secret lives in two places:

1. **Google Secret Manager** in `watchtower-observe`, which is what deploys
   read. Payloads are replicated to `europe-west3` only.
2. **gopass** as `watchtower/<id>`, the local copy. `scripts/env.sh`
   exports from it for owner-run commands.

The ids are the same in both, and
[`scripts/secret-names.txt`](../scripts/secret-names.txt) lists them all.
`scripts/bootstrap.sh` creates each one empty in Secret Manager, and
`scripts/secret.sh put <id>` stores a value in both places.
`scripts/secret.sh check` lists any secret still missing a value or a gopass
copy.

```bash
openssl rand -base64 48 | scripts/secret.sh put pulumi-passphrase
scripts/secret.sh put hcloud-token            # paste at the hidden prompt
scripts/secret.sh put ssh-private-key <./watchtower-root
scripts/secret.sh check
```

## Who reads what

- **The deploy workflow** has one Actions secret, `GCP_DEPLOYER_KEY`, a JSON
  key of `watchtower-deployer@watchtower-observe`. Each job's setup step uses
  it to read that job's secrets from Secret Manager into masked environment
  variables. The Pulumi programs read theirs with the same key while they
  run.
- `watchtower-deployer@` can read each listed secret through a grant on that
  secret, never `secretAccessor` on the project. It also has `dns.admin` on
  the one zone, so the cloud stack can write its records.
- **The image job** is the one exception. It runs on the shared DinD runner,
  where jobs can see each other's credentials, so it never gets the
  deployer key. It gets only the push token, as the Actions secret
  `REGISTRY_TOKEN`, copied from Secret Manager with
  `scripts/secret.sh gitea registry-push-token REGISTRY_TOKEN`.
- **The cluster** never touches Google: the apps program turns what it read
  into Kubernetes Secrets, which are encrypted in Pulumi state and in etcd.

A new version reaches the cluster on the next deploy: push to main, or
dispatch `deploy` with `kubespray=skip`.

Why a long-lived key: the Gitea runner cluster keeps Actions jobs away from
GKE Workload Identity on purpose (instance-wide runners, metadata server
blocked; see the gitea repo's `infra/pkg/runner`). A dedicated deploy runner
with its own identity would let `GCP_DEPLOYER_KEY` go. Until then, rotate it
every 90 days.

## Gitea Actions secrets

| Secret | Local copy | Notes |
|---|---|---|
| `GCP_DEPLOYER_KEY` | gopass `watchtower/gcp-deployer-key` | Not in Secret Manager: it is the key to it. `scripts/rotate-gcp-key.sh deployer` creates it, stores it in both places and deletes older keys |
| `REGISTRY_TOKEN` | Secret Manager and gopass `registry-push-token` | Gitea token, `write:package`; `scripts/secret.sh gitea registry-push-token REGISTRY_TOKEN` |

## Secret Manager (and gopass)

### Read by the deploy workflow

| Id | What | Used by |
|---|---|---|
| `pulumi-passphrase` | At least 32 random bytes (`openssl rand -base64 48`) | Both stacks' state encryption |
| `s3-admin-access-key`, `s3-admin-secret-key` | Hetzner S3 credential `admin` | Pulumi backend, MinIO provider, `verify.sh`; the only key the state bucket admits. The cloud program also reads the access key ID for the bucket policies |
| `hcloud-token` | Hetzner API token, read/write | Pulumi `cloud`, `verify.sh` |
| `hcloud-ccm-token` | Hetzner API token, read/write; separate so it can be rotated alone | Kubespray → `kube-system/hcloud` (CCM and hcloud-csi) |
| `ssh-private-key` | ed25519, root on the nodes (public half: `watchtower:sshPublicKey`) | Ansible |
| `registry-push-token` | Gitea token, `write:package` | Copied to the `REGISTRY_TOKEN` Actions secret |

### Read by the apps program

| Id | What |
|---|---|
| `grafana-admin-password` | Grafana's `admin`; `scripts/onboard-tenant.sh` reads the gopass copy |
| `wg-easy-password` | wg-easy's first-start admin password |
| `caddy-dns-key` | JSON key of `watchtower-caddy-dns01@` (DNS-01); `scripts/rotate-gcp-key.sh caddy` |
| `luks-passphrase` | Encrypts every hcloud-csi volume. **Losing it loses the volumes' data** |
| `registry-pull-token` | Gitea token, `read:package`, for image pulls |
| `hcloud-fip-token` | Hetzner token for fipd only |
| `s3-{loki,mimir,tempo,logship}-access-key` | Each component's S3 key ID. The cloud program reads these too, for the bucket policies |
| `s3-{loki,mimir,tempo,logship}-secret-key` | Its secret |

## Stack config

Both `Pulumi.prod.yaml` files hold public values only, and a test fails if
either gains a `secure:` value. `watchtower:caddyImage` and
`watchtower:fipdImage` are not committed: `deploy.yml` sets them to the
digests it just built.

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
