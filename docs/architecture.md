# Architecture

## Overview

Watchtower runs Mimir (metrics), Loki (logs), Tempo (traces) and Grafana
(UI) for several tenants, as podman containers on three ARM servers in
Hetzner's Falkenstein location (fsn1), behind one small ARM proxy, with
their Object Storage in the same location. Clients
ship telemetry over WireGuard to the private endpoint
`watchtower.jasonmross.dev`, which resolves to the in-tunnel address 10.8.0.1
and nothing else.

```
                          Internet
                             │ UDP 51820 (WireGuard) to vpn.watchtower.jasonmross.dev
                ┌────────────┴────────────┐
                │ Hetzner Cloud Firewalls │ 22/tcp ← admin + CI (34.26.149.196), all hosts
                │ (public interfaces)     │ 51820/udp ← wireguardAllowCidrs, proxy only
                └────────────┬────────────┘
 ┌ watchtower-proxy (cax11, ARM) ────────────────────────────────────────────────────┐
 │ wg-easy: wg0 10.8.0.1/24 (peers, split tunnel)                                    │
 │ Caddy + Coraza: TLS for watchtower.jasonmross.dev (DNS-01), on 10.8.0.1 only      │
 │   :443 Grafana ×3 · :3100 Loki ×3 · :8080 Mimir ×3 · :3200 Tempo frontends ×2     │
 │   :4317/:4318 Tempo distributors ×3 · :51821 wg-easy UI                           │
 └────────── wg1 mesh 10.30.0.0/24, over the private network 10.20.1.0/24 ───────────┘
 ┌ watchtower-1 ──────────┐ ┌ watchtower-2 ──────────┐ ┌ watchtower-3 ──────────┐
 │ cax31 ARM, LUKS volume │ │ same                   │ │ same                   │
 │ Loki (all, RF 3)       │ │ Loki                   │ │ Loki                   │
 │ Mimir (all, RF 3)      │ │ Mimir                  │ │ Mimir                  │
 │ Kafka broker+controller│ │ Kafka                  │ │ Kafka                  │
 │ Tempo: distributor,    │ │ Tempo: same five,      │ │ Tempo: same five       │
 │  live-store (zone a),  │ │  live-store (zone b),  │ │  (zone c)              │
 │  querier, worker,      │ │  query frontend,       │ │                        │
 │  generator, frontend,  │ │  backend scheduler     │ │                        │
 │  block builder         │ │                        │ │                        │
 │ etcd · Patroni/PG 18   │ │ etcd · Patroni/PG 18   │ │ etcd · Patroni/PG 18   │
 │ Grafana · Fluent Bit   │ │ Grafana · Fluent Bit   │ │ Grafana · Fluent Bit   │
 └───────────┬────────────┘ └───────────┬────────────┘ └───────────┬────────────┘
             └──────────────────────────┼──────────────────────────┘
                                        ▼  the cluster S3 key
                         Hetzner Object Storage (fsn1)
     <prefix>-loki · -mimir-blocks · -mimir-ruler · -mimir-alertmanager
     <prefix>-tempo · -logs-archive and -postgres-backups (write-only for the cluster key)
     <prefix>-pulumi-state (admin only)

  Cloud DNS (watchtower-observe), delegated from jasonmross.dev:
    watchtower.jasonmross.dev      A 10.8.0.1        (private, in-tunnel)
    vpn.watchtower.jasonmross.dev  A <proxy IPv4>    (where peers connect)
```

## The pieces

| Layer | What | Where it's defined |
|---|---|---|
| Hetzner | Network, four servers (spread placement, delete-before-replace), primary IPs, data volumes, two firewalls, SSH host keys | `infra/cloud` (Pulumi) |
| Storage | Buckets with lifecycle rules and per-key bucket policies | `infra/cloud/storage.go` |
| DNS | Records in the zone `scripts/bootstrap.sh` created and delegated | `infra/cloud/dns.go` |
| Hosts | Updates, journald, SELinux, nftables, fail2ban, the wg1 mesh, the LUKS volume, gated reboots, Fluent Bit | `ansible/roles/{base,firewall,fail2ban,mesh,storage,reboot,logship}` |
| Services | One role each; every container a quadlet in `/etc/containers/systemd` | `ansible/roles/{loki,mimir,kafka,tempo,etcd,patroni,grafana,edge}` |
| Images | Caddy, wg-easy (on Alpine) and Patroni, built natively on the arm64 runner, checked and scanned; tagged version, Alpine release and revision, and reused while the tag stands | `build/`, `scripts/{image-tag,build-image,publish-image}.sh` |

## Data flow

1. **Clients** run Grafana Alloy (`config/alloy/config.alloy.example`) with
   PII scrubbing, as WireGuard peers.
2. Alloy sends **logs** to `:3100`, **metrics** to `:8080` and **traces** to
   `:4317`/`:4318` on `watchtower.jasonmross.dev`, over TLS, with the tenant
   in `X-Scope-OrgID`.
3. Caddy terminates TLS on 10.8.0.1 and spreads each port across the nodes
   over the mesh, health-checking each backend and retrying a failed
   connection on the next node. Grafana on `:443` sits behind the Coraza WAF
   (OWASP CRS, detection-only).
4. **Loki and Mimir** each run on every node as one monolithic process;
   every write goes to three ingesters, one per node.
5. **Tempo's** distributors write spans to Kafka (three copies, two in sync
   to accept). Each node's live-store serves recent traces for its zone; the
   block builder writes blocks to S3; the scheduler and workers compact and
   enforce retention; the metrics generators turn spans into Mimir series.
6. **Grafana** (three instances, one Postgres database) queries the
   backends through `*.internal` names that resolve to all three nodes, the
   local one first.
7. **Fluent Bit** on every host ships the journal (every container logs
   there) and the audit log to the log archive.
8. **Every night** the Postgres leader dumps Grafana's database to
   `-postgres-backups`, kept 90 days, and reports to Healthchecks.io: a
   failed run alerts at once, a missed night when its grace runs out.
9. **Every 5 minutes** each host checks its own services, disks and
   SELinux, and reports to its own Healthchecks.io check, which emails when
   it is unhealthy twice in a row or goes 15 minutes without reporting.

## What each failure costs

| Failure | Effect |
|---|---|
| Any one data node | Nothing visible to users: Loki, Mimir, Kafka and etcd keep their quorums, Patroni fails over in about 30 s and Grafana follows by itself, Caddy skips the node. Its Healthchecks.io check emails within 15 minutes; the stack has no spare until it is back |
| watchtower-1 | Tempo's block builder pauses until moved (`group_vars/all/placement.yml`); Kafka keeps 24 h of traces |
| watchtower-2 | Tempo's compaction and retention (scheduler) pause until moved |
| The proxy | Ingest and the UI are down until it is rebuilt (10–15 minutes); Alloy buffers and retries. Its Healthchecks.io check emails within 15 minutes |
| A mistake in Grafana's database (a deleted dashboard, a bad upgrade) | Every replica has it too; restore last night's dump (runbook, "Grafana database backups") |

## Why it is built this way

- **No Kubernetes.** Three cpx42s for Kubernetes cost $246 a month in
  servers alone. Podman quadlets on 3× cax31 plus a cax11 cost about $100
  all in, and fill the account's 26-vCPU cap exactly.
- **High availability without an orchestrator.** Loki's "HA monolithic"
  mode and Mimir's scaled monolithic mode both take three plain replicas on
  memberlist. Tempo 3 can only scale in microservices mode, which needs
  Kafka; Grafana can only scale on a shared SQL database, so Postgres is
  kept highly available by Patroni with etcd.
- **One front box.** A second one (keepalived and a Floating IP) is the
  upgrade once the account may exceed 26 vCPUs. Hetzner load balancers carry
  no UDP, so they can't front WireGuard.
- **Host networking, mesh addresses.** Every container uses the host's
  network and binds only its mesh address, so nothing is NATed or forwarded
  and the firewall has one chain to reason about. Services on one host get
  distinct ports (`group_vars/all/ports.yml`).
- **Discovery through `/etc/hosts`.** `AddHost=` names list all three
  nodes, local first; Go's dialer moves to the next address when one fails.
  Grafana reaches Postgres with a multi-host DSN and
  `target_session_attrs=read-write`, so it always writes to the primary.
- **Rolling deploys.** The first deploy starts the nodes together (etcd and
  Kafka need a quorum); after that one node at a time, each checked healthy
  before the next, and a Patroni restart moves leadership away first.
- **Pinned SSH host keys.** The cloud stack generates each host's key and
  hands it over through cloud-init, so Ansible connects with strict host key
  checking from the first run, CI included.
- **No secrets in the repo, none in plaintext in state.** Every secret lives
  in Secret Manager (`watchtower-observe`, payloads in europe-west3) with a
  gopass copy. The deploy holds one key and reads the rest with it; on the
  hosts they become podman secrets, never unit-file environment.

## Security layers

| Layer | Control |
|---|---|
| Edge | Hetzner Cloud Firewalls: the nodes take nothing on their public addresses; the proxy takes SSH from the deploy runners only and WireGuard from `wireguardAllowCidrs`. People SSH in over the VPN, and to a node through the proxy |
| Host | nftables (no firewalld) mirroring the cloud firewalls; SSH to a node only from the proxy's private address; on the mesh, nodes reach each other fully and the proxy only Caddy's backend ports; Kafka, etcd and Postgres from nodes only. SELinux enforcing; fail2ban (sshd, recidive); security updates nightly, reboots one host a week, gated on the others' health |
| Containers | Non-root where the image allows, read-only roots, every capability dropped but what each needs; only wg-easy (wg0, iptables) and Fluent Bit (the host's journal and audit log) run without SELinux confinement |
| Credentials | Two S3 keys, fenced by bucket policies: the cluster key can't touch Pulumi state and can only write to the archive and the backups. Every secret in Secret Manager, read by the deployer through a grant per secret; the image jobs hold only a push key for the one registry repo |
| Encryption | WireGuard (clients, and every byte between hosts), TLS on every client-facing endpoint, LUKS volumes |
| WAF | Coraza with the OWASP CRS on Grafana (detection-only until tuned) |

## Lifecycle

- **`ci.yml`** checks every pull request: Go (100% coverage); Ansible syntax
  and lint, every host's firewall through `nft --check`; every rendered
  config through the program that reads it (quadlet, Loki, Mimir, Tempo,
  Fluent Bit; shellcheck for the host scripts); our images (native builds,
  their configs checked with the built image, Trivy, a new tag for any
  change); Semgrep; shellcheck, actionlint, the Alloy example.
- **`deploy.yml`** on merge to main: our images (to Artifact Registry, on
  Alpine's newest patch release), `infra/cloud`,
  `ansible/playbooks/site.yml`, then `scripts/verify.sh`.
