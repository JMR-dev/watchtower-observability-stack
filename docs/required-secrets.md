# Required secrets

Nothing secret is committed, encrypted or not: the repo is mirrored
publicly. Every secret lives in two places:

1. **Google Secret Manager** in `watchtower-observe`, which is what deploys
   read. Payloads are replicated to `europe-west3` only.
2. **gopass** as `watchtower/<id>`, the local copy. `scripts/env.sh`
   exports from it for owner-run commands.

The ids are the same in both; the tables below list them all.
`scripts/secret.sh put <id>` stores a value in both places, for any Secret
Manager id. `scripts/bootstrap.sh` creates, empty, every secret the deploy
workflow reads (its setup steps' `secrets:` lines; `scripts/secret.sh
deploy-ids` prints them) and grants the deployer each. A new secret the
deploy needs therefore goes in `deploy.yml` first, then `bootstrap.sh`
again. `scripts/secret.sh check` lists any secret still missing a value or
a gopass copy: every one the deploy reads, and every one labelled
`app=watchtower` in Secret Manager.

```bash
openssl rand -base64 48 | scripts/secret.sh put pulumi-passphrase
scripts/secret.sh put hcloud-token            # paste at the hidden prompt
scripts/secret.sh put ssh-private-key <./watchtower-root
scripts/secret.sh check
```

## Who reads what

- **The deploy workflow** has one Actions secret for Secret Manager,
  `GCP_DEPLOYER_KEY`, a JSON key of `watchtower-deployer@watchtower-observe`.
  The cloud and hosts jobs' setup step uses it to read that job's secrets
  into masked environment variables (key files as 0600 files). The Pulumi
  program reads the access key IDs for its bucket policies with the same
  key while it runs.
- `watchtower-deployer@` can read each listed secret but `gar-push-key`,
  through a grant on that secret, never `secretAccessor` on the project. It
  also has `dns.admin` on the one zone, so the cloud stack can write its
  records.
- **The image jobs** run on the shared DinD runners, where jobs can see
  each other's credentials, so they never get the deployer key. They get
  only `GAR_PUSH_KEY`, which can push to the one Artifact Registry repo,
  copied from Secret Manager by `scripts/rotate-gcp-key.sh pusher`.
- **The hosts** get theirs from Ansible, as podman secrets (root-only, out
  of unit files and container listings): the cluster S3 key, the LUKS key,
  the pull key, Grafana's, Postgres's and Patroni's passwords, wg-easy's
  first-start password, Caddy's DNS-01 key and the Healthchecks.io ping
  URLs (the backup's, and the host's own). A new value reaches them on
  the next deploy, and only the containers that use it restart.

Why a long-lived key: the Gitea runner cluster keeps Actions jobs away from
GKE Workload Identity on purpose (instance-wide runners, metadata server
blocked; see the gitea repo's `infra/pkg/runner`). A dedicated deploy runner
with its own identity would let `GCP_DEPLOYER_KEY` go. Until then, rotate it
every 90 days.

## Gitea Actions secrets

| Secret | Local copy | Notes |
|---|---|---|
| `GCP_DEPLOYER_KEY` | gopass `watchtower/gcp-deployer-key` | Not in Secret Manager: it is the key to it. `scripts/rotate-gcp-key.sh deployer` creates it, stores it in both places and deletes older keys |
| `GAR_PUSH_KEY` | Secret Manager and gopass `gar-push-key` | JSON key of `watchtower-image-pusher@`, writer on the `watchtower` repo only; `scripts/rotate-gcp-key.sh pusher` |

## Secret Manager (and gopass)

### Read by the cloud job

| Id | What | Used by |
|---|---|---|
| `pulumi-passphrase` | At least 32 random bytes (`openssl rand -base64 48`) | The stack's state encryption |
| `hcloud-token` | Hetzner API token, read/write (Hetzner tokens are project-wide) | Pulumi |
| `s3-admin-access-key`, `s3-admin-secret-key` | Hetzner S3 credential `admin` | Pulumi backend, MinIO provider, `verify.sh`; the only key the state bucket admits |

### Read by the hosts job, installed on the hosts

| Id | What |
|---|---|
| `ssh-private-key` | ed25519, root on the hosts (public half: `watchtower:sshPublicKey`); Ansible connects with it |
| `s3-cluster-access-key`, `s3-cluster-secret-key` | Hetzner S3 credential `cluster`: Loki, Mimir, Tempo, Fluent Bit and the Postgres backup. The cloud program reads the access key ID too, for the bucket policies |
| `luks-passphrase` | Encrypts every host's data volume. **Losing it loses the volumes' data** |
| `gar-pull-key` | JSON key of `watchtower-image-puller@`, reader on the `watchtower` repo; the hosts pull Caddy and Patroni with it. `scripts/rotate-gcp-key.sh puller` |
| `grafana-admin-password` | Grafana's `admin`; `scripts/onboard-tenant.sh` reads the gopass copy |
| `grafana-secret-key` | The same on all three Grafanas: it encrypts datasource secrets in the shared database |
| `grafana-db-password` | Grafana's Postgres role |
| `postgres-superuser-password`, `postgres-replication-password` | Patroni's `postgres` and `replicator` |
| `patroni-restapi-password` | Patroni's REST API (switchover, restart) |
| `wg-easy-password` | wg-easy's first-start admin password |
| `caddy-dns-key` | JSON key of `watchtower-caddy-dns01@` (DNS-01); `scripts/rotate-gcp-key.sh caddy` |
| `healthchecks-pg-backup-url` | Ping URL of the Healthchecks.io check of the nightly backup (docs/runbook.md, "First deploy"). The nightly backup pings it, or its `/fail` when a run fails. Anyone holding it can ping the check |
| `healthchecks-host-urls` | One JSON object, host name to the ping URL of its Healthchecks.io check, written by `scripts/healthchecks.sh`. Each host gets only its own URL |

### Owner only

| Id | What |
|---|---|
| `gar-push-key` | The `GAR_PUSH_KEY` Actions secret's source. Never granted to the deployer, so a leaked deployer key can't push images |
| `healthchecks-jasonmross-dev-api-key` | Read-write API key of the Healthchecks.io project `jasonmross.dev`, for `scripts/healthchecks.sh`. Never granted to the deployer: the deploy holds ping URLs, which can't pause, change or delete a check |

### Written by the deploy

| Id | What |
|---|---|
| `wireguard-owner-peer` | The owner's first WireGuard peer config, created by the first deploy in wg-easy (client `owner`). The deployer holds `secretVersionAdder` on it alone: it may add a version, never read one. Fetch it with `scripts/secret.sh pull wireguard-owner-peer`; `secret.sh check` reports it pending until the first deploy |

## Stack config

`infra/cloud/Pulumi.prod.yaml` holds public values only, and a test fails if
it gains a `secure:` value.

## What each S3 key can reach

Bucket policies (Hetzner's `p<project>:<key>` principals) deny every key but
the admin key and the cluster key:

| Bucket | Admin | Cluster |
|---|---|---|
| `-pulumi-state` | ✓ | |
| `-loki`, `-mimir-blocks`, `-mimir-ruler`, `-mimir-alertmanager`, `-tempo` | ✓ | ✓ |
| `-logs-archive` | ✓ | write only, not `gdpr-audit/` |
| `-postgres-backups` | ✓ | write only |

A side effect: the Hetzner Console can no longer list these buckets'
objects. Use the admin key with `aws s3`.
