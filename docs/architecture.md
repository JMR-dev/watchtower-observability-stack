# Architecture

## Overview

Watchtower is a three-node Kubernetes cluster in Hetzner's Nuremberg location
(nbg1). It runs Mimir (metrics), Loki (logs), Tempo (traces) and Grafana (UI)
for several tenants. Clients ship telemetry over WireGuard to the private
endpoint `watchtower.jasonmross.dev`, which resolves to the in-tunnel address
10.8.0.1 and nothing else.

```
                      Internet
                         │ UDP 51820 (WireGuard) to the Floating IP
            ┌────────────┴────────────┐
            │ Hetzner Cloud Firewall  │ 22,6443/tcp ← admin + CI (34.26.149.196)
            │ (public interfaces)     │ 51820/udp  ← wireguardAllowCidrs
            └────────────┬────────────┘
   ┌─────────────────────┼─────────────────────────────────────────┐
   │ watchtower-1..3: CPX42, AlmaLinux 10, SELinux enforcing       │
   │ host firewall: nftables, mirroring the cloud firewall         │
   │ private network 10.20.1.0/24; Cilium (pod traffic encrypted   │
   │ with WireGuard); control plane + etcd + workloads on each     │
   │                                                               │
   │  ns watchtower-edge          ns watchtower                    │
   │  ┌──────────────────┐        ┌───────────────────────────┐    │
   │  │ edge pod         │ :3100  │ Loki (distributed)        │    │
   │  │  wg-easy  wg0 ───┼───────►│ Mimir (monolithic)        │    │
   │  │  10.8.0.1        │ :8080  │ Tempo (single binary)     │    │
   │  │  Caddy + Coraza  │ :3200  │ Grafana                   │    │
   │  │  TLS (DNS-01)    │ :443…  └────────────┬──────────────┘    │
   │  └──────────────────┘                     │ S3, one key each   │
   │  ns watchtower-fip: fipd ─► Hetzner API   │                    │
   │  ns logging: Fluent Bit (every node) ─────┼──► log archive     │
   └───────────────────────────────────────────┼────────────────────┘
                                               ▼
                         Hetzner Object Storage (nbg1)
     <prefix>-loki · -mimir-blocks · -mimir-ruler · -mimir-alertmanager
     <prefix>-tempo · -logs-archive · -pulumi-state

  Cloud DNS (watchtower-observe), delegated from jasonmross.dev:
    watchtower.jasonmross.dev      A 10.8.0.1        (private, in-tunnel)
    vpn.watchtower.jasonmross.dev  A <Floating IP>   (where peers connect)
    api.watchtower.jasonmross.dev  A <nodes 1-3>     (Kubernetes API)
```

## The pieces

| Layer | What | Where it's defined |
|---|---|---|
| Hetzner | Network, 3 servers (spread placement), primary IPs, firewall, Floating IP, SSH host keys | `infra/cloud` (Pulumi) |
| Storage | Buckets with lifecycle rules and per-key bucket policies | `infra/cloud/storage.go` |
| DNS | Records in the zone `scripts/bootstrap.sh` created and delegated | `infra/cloud/dns.go` |
| Nodes | Updates, journald, SELinux, nftables firewall, fail2ban, wireguard module, Floating IP on eth0 | `ansible/roles` |
| Kubernetes | Kubespray 2.32: Kubernetes 1.36, containerd, Cilium, hcloud CCM, etcd encryption, audit log | `ansible/inventory/group_vars` |
| Workloads | Charts and manifests | `infra/apps` |

## Data flow

1. **Clients** run Grafana Alloy (`config/alloy/config.alloy.example`) with
   PII scrubbing, as WireGuard peers.
2. Alloy sends **logs** to `:3100`, **metrics** to `:8080` and **traces** to
   `:4317`/`:4318` on `watchtower.jasonmross.dev`, over TLS, with the tenant
   in `X-Scope-OrgID`.
3. Caddy, in the edge pod, terminates TLS on 10.8.0.1 and proxies to Loki's
   distributors, query frontend, compactor and ruler; to Mimir; to Tempo; and
   to Grafana on `:443`, behind the Coraza WAF (OWASP CRS, detection-only).
4. Loki, Mimir and Tempo write to their buckets with their own S3 keys. WALs
   live on LUKS-encrypted Hetzner Volumes (hcloud-csi).
5. Grafana queries the backends inside the cluster, one datasource per tenant.
6. Fluent Bit ships every container log, every node's journal and the API
   server audit log to the log archive.

## Why it is built this way

- **wg-easy and Caddy share one pod.** Caddy is reachable at wg0's address
  with no forwarding, NAT or internal load balancer, and peers route only
  10.8.0.0/24 through the tunnel.
- **A Floating IP plus fipd for the VPN.** Hetzner load balancers carry no
  UDP, so the edge pod takes UDP 51820 with a hostPort on whichever node runs
  it. Every node has the Floating IP on eth0. fipd routes it to the node of
  the newest Ready edge pod on a Ready node, ignoring pods stuck on dead nodes
  (which the upstream controller would follow). A drain moves the VPN in
  about a minute, a dead node in about seven (30 s eviction, then
  Kubernetes' six-minute force-detach of its volumes).
- **The API by DNS round-robin.** `api.watchtower.jasonmross.dev` lists the
  three control-plane nodes, and the firewall admits only admin and CI
  addresses, so there is no load balancer to pay for.
- **Mimir and Tempo as single processes.** Their 3.x distributed charts need
  Kafka. The metrics and trace volume doesn't justify it; logs are the
  intensive signal, so Loki runs distributed (three ingesters at RF 3, so a
  node reboot keeps quorum).
- **Two Pulumi programs.** `cloud` must exist before Kubespray can build the
  cluster that `apps` deploys into; Ansible runs between them.
- **Pinned SSH host keys.** The cloud stack generates each node's host key
  and hands it over through cloud-init, so Ansible connects with strict host
  key checking from the first run, CI included.
- **No secrets in the repo, none in plaintext in state.** Every secret lives
  in Secret Manager (`watchtower-observe`, payloads in europe-west3) with a
  gopass copy. The deploy workflow holds one key, reads its credentials with
  it, and the programs read the rest while they run; what they build from
  them is encrypted in state.

## Security layers

| Layer | Control |
|---|---|
| Edge | Hetzner Cloud Firewall: SSH and the API from admin/CI addresses only; WireGuard from `wireguardAllowCidrs` |
| Host | nftables ruleset (no firewalld) mirroring the cloud firewall, from the same address lists, and admitting everything from the other nodes and the pods; SELinux enforcing; fail2ban (sshd, recidive); security updates nightly, reboots by kured one node at a time |
| Cluster network | Cilium default-deny policies in every namespace we own; FQDN-scoped egress (S3, ACME, Cloud DNS, Hetzner API) |
| Pod security | `restricted` everywhere except the edge pod (NET_ADMIN for wg0) and Fluent Bit (host logs), which run `spc_t` |
| Credentials | One S3 key per component, fenced by bucket policies; the archive key can only write; the Hetzner token sits in fipd's namespace alone. Every secret in Secret Manager, read by the deployer through a grant per secret; the image job on the shared DinD runner never holds the deployer key |
| Encryption | WireGuard (clients, and pod-to-pod between nodes), TLS on every client-facing endpoint, LUKS volumes, etcd secret encryption. Caddy reaches the backends over plain HTTP, so a hop between two pods on the same node is not encrypted |
| WAF | Coraza with the OWASP CRS on Grafana (detection-only until tuned) |

## Lifecycle

- **`ci.yml`** checks every pull request: Go (100% coverage); every chart
  and every object `infra/apps` builds, through kubeconform and a server-side
  dry run against a throwaway kube-apiserver of the cluster's version;
  Ansible syntax and lint, and the node firewall through `nft --check`; both
  images (build, Trivy, and the Caddyfile validated as the edge pod runs it);
  shellcheck, actionlint, the Alloy example.
- **`deploy.yml`** on merge to main: images, `infra/cloud`, the node
  baseline, Kubespray when its inputs changed or a node was created,
  `infra/apps`, then `scripts/verify.sh`.
