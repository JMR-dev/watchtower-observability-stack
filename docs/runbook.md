# Runbook

Everything below runs from a workstation with `gopass`, `pulumi`, `ansible`
(`ansible/requirements.txt`, installed with uv), `aws` and `gcloud`, after
`source scripts/env.sh`.

## First deploy

Secrets go to Secret Manager and gopass together, through
`scripts/secret.sh` ([required-secrets.md](required-secrets.md)). It needs
gcloud logged in as the owner of `watchtower-observe` and an unlocked
gopass.

1. **Hetzner Console**, project `watchtower-observe-prod`:
   - one API token, read/write (Hetzner tokens are project-wide anyway);
   - two S3 credentials: `admin` and `cluster`.
2. **Store every secret.** Paste each token or key at the hidden prompt;
   generate the rest:
   ```bash
   scripts/secret.sh put hcloud-token
   for k in admin cluster; do
     scripts/secret.sh put "s3-$k-access-key"
     scripts/secret.sh put "s3-$k-secret-key"
   done
   ssh-keygen -t ed25519 -N '' -C watchtower-root -f ./watchtower-root
   scripts/secret.sh put ssh-private-key <./watchtower-root && shred -u ./watchtower-root
   openssl rand -base64 48 | scripts/secret.sh put pulumi-passphrase
   openssl rand -base64 48 | scripts/secret.sh put luks-passphrase
   openssl rand -base64 48 | scripts/secret.sh put grafana-secret-key
   for id in grafana-admin-password grafana-db-password postgres-superuser-password \
       postgres-replication-password patroni-restapi-password wg-easy-password; do
     openssl rand -base64 24 | tr -d '/+=' | scripts/secret.sh put "$id"
   done
   ```
3. **Stack config.** In `infra/cloud/Pulumi.prod.yaml` set `sshPublicKey`
   (`watchtower-root.pub`) and tighten `adminCidrs`. Commit it.
4. **Bootstrap** (state bucket, DNS zone and delegation, service accounts,
   the image registry, the secrets' access grants), then the four GCP keys:
   ```bash
   source scripts/env.sh
   scripts/bootstrap.sh
   dig +short NS watchtower.jasonmross.dev   # four ns-cloud-* names
   scripts/rotate-gcp-key.sh deployer        # Actions secret GCP_DEPLOYER_KEY + gopass
   scripts/rotate-gcp-key.sh caddy           # secret caddy-dns-key
   scripts/rotate-gcp-key.sh pusher          # secret gar-push-key + Actions secret GAR_PUSH_KEY
   scripts/rotate-gcp-key.sh puller          # secret gar-pull-key
   scripts/secret.sh check                   # nothing missing
   ```
   Delete anything the leftover listing shows that the new stack doesn't own.
5. **Initialise the stack** (`env.sh` again, now that the deployer key is in
   gopass):
   ```bash
   source scripts/env.sh
   cd infra && go build -o bin/cloud ./cloud
   (cd cloud && pulumi stack init prod --secrets-provider passphrase)
   ```
   Commit `Pulumi.prod.yaml`: `stack init` only adds the `encryptionsalt`.
6. **Gitea:** in Settings → Branches, protect main and require the `ci`
   checks: `go`, `ansible`, `configs`, `images (caddy)`, `images (patroni)`,
   `semgrep`, `shell`, `alloy`.
7. **Merge to main.** `deploy.yml` builds both images, creates the hosts,
   installs everything (all three nodes at once the first time), and
   verifies it end to end.
8. **First peer:** the wg-easy UI is only reachable from a peer, so create
   the first one through an SSH tunnel to the proxy:
   ```bash
   ssh -L 51822:127.0.0.1:51822 root@$(cd infra/cloud && pulumi stack output proxyIpv4)
   # http://127.0.0.1:51822, user admin, the wg-easy password
   ```
   Create a client, import its config, connect, then use the TLS UI on
   `https://watchtower.jasonmross.dev:51821` from then on.
9. Open `https://watchtower.jasonmross.dev` (Grafana, user `admin`) and point
   a test Alloy (`config/alloy/config.alloy.example`) at the stack.

## Host access

```bash
source scripts/env.sh
(cd infra/cloud && pulumi stack output inventory >../../ansible/inventory/hosts.yml \
  && pulumi stack output knownHosts >../../ansible/inventory/known_hosts)
(cd ansible && ansible all -m ping)
ssh root@<host>             # the key from env.sh's ssh-agent
```

SSH answers only on admin and CI addresses (`adminCidrs`, `ciCidrs`).

Every service is a quadlet: `/etc/containers/systemd/<name>.container`
generates `<name>.service`.

```bash
systemctl status loki mimir kafka etcd patroni grafana 'tempo-*'
journalctl -u loki -f                   # every container logs to the journal
podman ps
```

Change a service through its role and a deploy, never by hand: the next
deploy would put it back.

## WireGuard peers

Peers are managed in the wg-easy UI at `https://watchtower.jasonmross.dev:51821`
(from a peer). Each client config points at `vpn.watchtower.jasonmross.dev`
(the proxy) and routes only 10.8.0.0/24. Revoke a peer by disabling or
deleting it in the UI; it takes effect at once.

## Reboots

dnf-automatic installs security updates nightly and never reboots. When one
needs a reboot, `watchtower-reboot.timer` reboots the host in its window,
Sunday UTC: the proxy at 07:00, nodes 1, 2, 3 at 08:00, 09:00, 10:00. A node
first checks that the others' Loki and Mimir are ready, that Kafka is fully
replicated and that Patroni has a leader and two streaming replicas; if not,
it skips the week. If it leads Postgres, it hands leadership to a replica
first.

```bash
journalctl -u watchtower-reboot --since -7d    # what it decided
needs-restarting -r                            # pending?
systemctl start watchtower-reboot.service      # run the gate now
```

The proxy's reboot is a minute of no ingest and no UI.

## Host firewall

Each host runs a raw nftables ruleset in its own table, `inet watchtower`
(`ansible/roles/firewall`), loaded by `watchtower-nftables.service`. It
mirrors the Hetzner Cloud Firewalls from the same `adminCidrs`, `ciCidrs`
and `wireguardAllowCidrs`. On the mesh (wg1), nodes reach each other fully
and the proxy only the ports Caddy proxies to. Kafka, etcd, Patroni and
Postgres have no authentication of their own beyond Postgres's: the
firewall is what keeps them to the nodes. firewalld is masked.

```bash
nft list table inet watchtower
journalctl -k -g 'nft-drop' --since -1h      # what it dropped (sampled)
systemctl reload watchtower-nftables         # after editing the file by hand
```

**Never run `nft flush ruleset`, and leave `nftables.service` masked** (its
reload and stop do the same): it wipes every table, fail2ban's and wg-easy's
included. If it happens, reboot the host.

## Postgres (Patroni)

```bash
podman exec patroni patronictl -c /etc/patroni/patroni.yml list
podman exec patroni patronictl -c /etc/patroni/patroni.yml switchover --leader <node> --force
```

A dead primary fails over in about 30 seconds: etcd's leader key expires
and a replica no more than 1 MB behind takes over. The Grafanas reconnect to
whichever node accepts writes (`target_session_attrs=read-write`). A member
that comes back behind is rewound or recloned by Patroni.

## Kafka

```bash
podman exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server=<mesh-ip>:9092 \
  --describe --topic tempo-traces
podman exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server=<mesh-ip>:9092 \
  --describe --under-replicated-partitions     # empty when healthy
```

Three brokers, each also a KRaft controller; every partition three copies,
two in sync to accept a write. A broker's data lives on its node's volume,
so a rebuilt node rejoins with its log and catches up.

## Moving a Tempo singleton

The block builder (node 1) and the backend scheduler (node 2) run once
each. If their node is down for long, move them: change
`tempo_block_builder_host` or `tempo_backend_scheduler_host` in
`ansible/inventory/group_vars/all/placement.yml` and merge. The deploy stops
the component on the old node and starts it on the new one. Kafka keeps 24
hours of traces for the block builder to catch up on.

## Rebuilding a host

Servers are replaced **delete-first**: the account's 26-vCPU cap has no room
for the new server next to the old one. Each host's primary IPs, SSH host
key and data volume survive, so a rebuilt node comes back with its address,
its known_hosts entry, and its Loki WAL, Kafka log, etcd member and Postgres
data.

```bash
source scripts/env.sh
cd infra/cloud
pulumi up --replace 'urn:pulumi:prod::watchtower-cloud::hcloud:index/server:Server::watchtower-2'
```

Then dispatch `deploy.yml`. Ansible reinstalls the host and gives it a new
mesh key; every other host's wg1 picks it up in the same run. A rebuild
from CI instead needs `allow_replace=true` (the preview guard refuses
otherwise).

## Log archive

```bash
aws --endpoint-url https://nbg1.your-objectstorage.com --region nbg1 \
  s3 ls s3://jmr-watchtower-logs-archive/containers/$(date -u +%Y/%m/%d)/ --recursive
aws --endpoint-url https://nbg1.your-objectstorage.com --region nbg1 \
  s3 cp s3://jmr-watchtower-logs-archive/journal/2026/10/24/03/watchtower-1-0412-<uuid>.gz - | zcat | head
```

Prefixes: `containers/`, `journal/`, `audit/` (all expire after 90 days) and
`gdpr-audit/` (kept). Fluent Bit uploads about every five minutes. The
cluster key can only write there; reading needs the admin key.

## GDPR right to erasure

```bash
source scripts/env.sh
scripts/gdpr-purge.sh team-alpha '{user_id="abc-123"}' 2025-01-01T00:00:00Z
```

Loki's compactor processes deletes after 2 hours. The record goes to
`gdpr-audit/` in the log archive. Mimir and Tempo have no per-record delete;
their 90- and 30-day retention is the erasure window.

## Credential rotation

Every secret but `GCP_DEPLOYER_KEY` is stored with `scripts/secret.sh put
<id>`, which adds a new version in Secret Manager and replaces the gopass
copy. The hosts get it on the next deploy (push to main, or dispatch
`deploy.yml`); only the containers that use it restart.

| Credential | How |
|---|---|
| `GCP_DEPLOYER_KEY` | `scripts/rotate-gcp-key.sh deployer` (every 90 days) |
| Caddy DNS-01 key | `scripts/rotate-gcp-key.sh caddy`, then deploy |
| Image push key | `scripts/rotate-gcp-key.sh pusher` (updates `GAR_PUSH_KEY` too) |
| Image pull key | `scripts/rotate-gcp-key.sh puller`, then deploy |
| Hetzner token | new token in the Console → `secret.sh put hcloud-token` → delete the old one (only Pulumi uses it) |
| Cluster S3 key | new key → `secret.sh put s3-cluster-access-key` and `-secret-key` → deploy (the bucket policies and every service follow) → delete the old key |
| Admin S3 key | new key → `secret.sh put s3-admin-access-key` and `-secret-key` → `source scripts/env.sh && scripts/bootstrap.sh` (state bucket policy) → deploy → delete the old key |
| Grafana, Postgres, Patroni passwords | `secret.sh put <id>`, then deploy. Postgres passwords change in the database too: run `ALTER ROLE` as the superuser (`podman exec -it patroni psql`) before the deploy |
| `grafana-secret-key` | don't, unless compromised: it encrypts datasource secrets in the database, which would have to be re-entered |
| `luks-passphrase` | `cryptsetup luksAddKey` on every host with the new one, `secret.sh put luks-passphrase`, deploy, then `luksRemoveKey` the old |
| Pulumi passphrase | `pulumi stack change-secrets-provider passphrase` with the new one, then `secret.sh put pulumi-passphrase` |
| Hosts' SSH key | new key → `watchtower:sshPublicKey` and `/root/.ssh/authorized_keys` on every host → `secret.sh put ssh-private-key` |

Old versions stay in Secret Manager's history until destroyed:
`gcloud secrets versions destroy <n> --secret <id> --project watchtower-observe`.

## Common issues

| Symptom | Likely cause | Fix |
|---|---|---|
| Deploy stops at "Destructive changes to guarded resources" | The preview would replace a server, IP, volume or bucket | Read the listed URNs; if intended, dispatch with `allow_replace=true` |
| Ansible "Host key verification failed" | `known_hosts` stale or missing | Re-export `knownHosts` from the cloud stack |
| A service won't start | Its config or a secret | `journalctl -u <name> -n 100`; `systemctl cat <name>` shows the generated unit |
| A node's services can't reach each other | wg1 down or a stale peer key | `wg show wg1` (a handshake per peer); a deploy re-renders every host's peers |
| Caddy has no certificate | DNS-01 failing | `journalctl -u caddy`; check the key and that the zone is delegated |
| A host drops traffic it should accept | The address isn't in the lists the ruleset mirrors | `journalctl -k -g nft-drop`; fix the cloud stack's CIDR config and merge |
| A container is blocked by SELinux | It needs host access it wasn't given | `ausearch -m avc -ts recent`; do not switch SELinux to permissive — fix the quadlet's volume labels or, as a last resort, `SecurityLabelDisable` for that one container |
| Loki "no org id" | Client without `X-Scope-OrgID` | Fix the Alloy config |
| Tempo queries miss recent traces | A live-store or the Kafka path | `systemctl status 'tempo-*'` on each node; Kafka's under-replicated partitions |

## Cost

About $100 a month (USD, no VAT): three cax31 ($74.97) and one cx23
($6.49), four primary IPv4s ($2.40), 100 GB of volumes ($7.67), the Object
Storage base fee (€6.49) and a dollar or two of GCP (DNS, Secret Manager,
Artifact Registry). No load balancers, no Floating IP.
