# Runbook

Everything below runs from a workstation with `gopass`, `pulumi`, `kubectl`,
`ansible` (from `ansible/requirements.txt`), `aws` and `gcloud`, after
`source scripts/env.sh`.

## First deploy

Secrets go to Secret Manager and gopass together, through
`scripts/secret.sh` ([required-secrets.md](required-secrets.md)). It needs
gcloud logged in as the owner of `watchtower-observe` and an unlocked
gopass.

1. **Hetzner Console** (project of your choice):
   - three API tokens, read/write: one for Pulumi, one for the
     cloud-controller-manager, one for fipd;
   - five S3 credentials: `admin`, `loki`, `mimir`, `tempo`, `logship`;
   - note the project ID from the Console URL (`/projects/<id>/servers`).

   **Gitea:** two tokens for the package registry, one `write:package`
   (pushes) and one `read:package` (pulls).
2. **Store every secret.** Paste each token or key at the hidden prompt;
   generate the rest:
   ```bash
   scripts/secret.sh put hcloud-token
   scripts/secret.sh put hcloud-ccm-token
   scripts/secret.sh put hcloud-fip-token
   for k in admin loki mimir tempo logship; do
     scripts/secret.sh put "s3-$k-access-key"
     scripts/secret.sh put "s3-$k-secret-key"
   done
   scripts/secret.sh put registry-push-token   # write:package
   scripts/secret.sh put registry-pull-token   # read:package
   ssh-keygen -t ed25519 -N '' -C watchtower-root -f ./watchtower-root
   scripts/secret.sh put ssh-private-key <./watchtower-root && shred -u ./watchtower-root
   openssl rand -base64 48 | scripts/secret.sh put pulumi-passphrase
   openssl rand -base64 24 | scripts/secret.sh put grafana-admin-password
   openssl rand -base64 24 | scripts/secret.sh put wg-easy-password
   openssl rand -base64 48 | scripts/secret.sh put luks-passphrase
   ```
3. **Stack config.** In `infra/cloud/Pulumi.prod.yaml` set
   `hetznerProjectId`, `sshPublicKey` (`watchtower-root.pub`) and tighten
   `adminCidrs`. Commit it.
4. **Bootstrap** (state bucket, DNS zone and delegation, service accounts,
   the secrets' access grants), then the two GCP keys:
   ```bash
   source scripts/env.sh
   scripts/bootstrap.sh
   dig +short NS watchtower.jasonmross.dev   # four ns-cloud-* names
   scripts/rotate-gcp-key.sh deployer        # Actions secret GCP_DEPLOYER_KEY + gopass
   scripts/rotate-gcp-key.sh caddy           # secret caddy-dns-key
   scripts/secret.sh gitea registry-push-token REGISTRY_TOKEN
   scripts/secret.sh check                   # nothing missing
   ```
   Delete anything the leftover listing shows that the new stack doesn't own.
5. **Initialise the stacks** (`env.sh` again, now that the deployer key is
   in gopass):
   ```bash
   source scripts/env.sh
   cd infra && go build -o bin/cloud ./cloud && go build -o bin/apps ./apps
   (cd cloud && pulumi stack init prod --secrets-provider passphrase)
   (cd apps && pulumi stack init prod --secrets-provider passphrase)
   ```
   Commit both `Pulumi.prod.yaml` files: `stack init` only adds the
   `encryptionsalt`.
6. **Gitea:** in Settings → Branches, protect main and require the `ci`
   checks: `go (fipd)`, `go (infra)`, `manifests`, `ansible`,
   `images (caddy)`, `images (fipd)`, `shell`, `alloy`.
7. **Merge to main.** `deploy.yml` creates the nodes, runs Kubespray (30–60
   minutes the first time), deploys the workloads and verifies them.
8. **First peer:** the TLS UI on `https://watchtower.jasonmross.dev:51821` is
   only reachable from a peer, so create the first one through a
   port-forward:
   ```bash
   kubectl -n watchtower-edge port-forward deploy/edge 51822:51822
   # http://127.0.0.1:51822, user admin, the wg-easy password
   ```
   Create a client, import its config, connect, then use the TLS UI on
   `:51821` from then on.
9. Open `https://watchtower.jasonmross.dev` (Grafana, user `admin`) and point
   a test Alloy (`config/alloy/config.alloy.example`) at the stack.

## Cluster access

```bash
source scripts/env.sh
(cd infra/cloud && pulumi stack output inventory >../../ansible/inventory/hosts.yml \
  && pulumi stack output knownHosts >../../ansible/inventory/known_hosts)
(cd ansible && ansible-playbook playbooks/kubeconfig.yml)   # -> ~/.kube/watchtower
kubectl get nodes
```

The API answers only on admin and CI addresses (`adminCidrs`, `ciCidrs`).

## WireGuard peers

Peers are managed in the wg-easy UI at `https://watchtower.jasonmross.dev:51821`
(from a peer). Each client config points at `vpn.watchtower.jasonmross.dev`
(the Floating IP) and routes only 10.8.0.0/24. Revoke a peer by disabling or
deleting it in the UI; it takes effect at once.

## The Floating IP

fipd moves the VPN address to the node running the edge pod. Check it:

```bash
kubectl -n watchtower-edge get pod -l app.kubernetes.io/name=edge -o wide
kubectl -n watchtower-fip logs deploy/fipd --tail=20
hcloud floating-ip list -l role=watchtower-vpn
```

**Edge pod stuck Terminating on a dead node** (the node will not come back
soon): the replacement waits up to six minutes for its two volumes. To hurry it:

```bash
kubectl -n watchtower-edge delete pod <old-pod> --grace-period=0 --force
```

**Manual override** (fipd down): `hcloud floating-ip assign watchtower-vpn
watchtower-N`, where N is the edge pod's node. fipd leaves a correct
assignment alone.

## Nodes

### Reboots
dnf-automatic installs security updates nightly and never reboots. When an
update needs a reboot, the `reboot-required` timer writes
`/var/run/reboot-required` and **kured** drains and reboots one node at a
time, Sundays 01:00–05:00 America/Chicago. During a node's reboot:
- Loki keeps accepting writes (three ingesters, RF 3, quorum 2);
- the edge pod moves (about a minute of VPN downtime) unless it was elsewhere;
- **Mimir is a singleton**: remote_write clients get a few minutes of 5xx and
  retry from their WAL. Grafana is a singleton too.

```bash
kubectl -n kube-system logs ds/kured --tail=50
ssh root@<node> cat /var/run/reboot-required   # present = pending
```

### Host firewall
Each node runs a raw nftables ruleset in its own table, `inet watchtower`
(`ansible/roles/firewall`), loaded by `watchtower-nftables.service`. It
mirrors the Hetzner Cloud Firewall from the same `adminCidrs`, `ciCidrs` and
`wireguardAllowCidrs`, and admits everything from the private network and
the pods. Pod-to-pod traffic is Cilium's to filter. firewalld is masked.

```bash
nft list table inet watchtower
journalctl -k -g 'nft-drop' --since -1h      # what it dropped (sampled)
systemctl reload watchtower-nftables         # after editing the file by hand
```

**Never run `nft flush ruleset` on a node, and leave `nftables.service`
masked** (its reload and stop do the same): it wipes every table, kube-proxy's,
Cilium's and portmap's included. If a node's rules were flushed anyway, drain
and reboot it rather than restarting agents one by one: portmap writes the
edge pod's hostPort rule only when that pod starts.

### Adding workers
Set `watchtower:nodeCount` above 3 and merge. `deploy.yml` creates the
servers and runs Kubespray's `scale.yml` (workers only; etcd stays at three).

### Replacing a control-plane node
A replacement of `watchtower-1..3` is refused unless dispatched with
`allow_replace=true`, because it touches etcd. The node keeps its primary IPs
and host key. Follow Kubespray's
[recover-control-plane](https://github.com/kubernetes-sigs/kubespray/blob/v2.32.0/docs/operations/recover-control-plane.md)
procedure (`kubernetes_sigs.kubespray.recover_control_plane`), then
dispatch `deploy.yml` with `kubespray=cluster`.

### Kubernetes upgrades
Bump `kube_version` (and Kubespray, in `ansible/requirements.*`) in a PR. A
push that changes `kube_version` fails the deploy on purpose; dispatch
`deploy.yml` with `kubespray=upgrade`, which drains and upgrades one node at
a time.

## Log archive

```bash
aws --endpoint-url https://nbg1.your-objectstorage.com --region nbg1 \
  s3 ls s3://jmr-watchtower-logs-archive/containers/$(date -u +%Y/%m/%d)/ --recursive
aws --endpoint-url https://nbg1.your-objectstorage.com --region nbg1 \
  s3 cp s3://jmr-watchtower-logs-archive/journal/2026/10/24/03/watchtower-1-0412-<uuid>.gz - | zcat | head
```

Prefixes: `containers/`, `journal/`, `audit/` (all expire after 90 days) and
`gdpr-audit/` (kept). Fluent Bit uploads about every five minutes. The
archive key can only write; reading needs the admin key.

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
copy. The cluster gets it on the next deploy: push to main, or dispatch
`deploy` with `kubespray=skip`.

| Credential | How |
|---|---|
| `GCP_DEPLOYER_KEY` | `scripts/rotate-gcp-key.sh deployer` (every 90 days) |
| Caddy DNS-01 key | `scripts/rotate-gcp-key.sh caddy`, then deploy |
| Hetzner tokens | new token in the Console → `secret.sh put hcloud-token` (or `hcloud-ccm-token`, `hcloud-fip-token`) → deploy → delete the old one |
| Component S3 keys | new key → `secret.sh put s3-<key>-access-key` and `-secret-key` → deploy (both stacks read them) → delete the old key |
| Admin S3 key | new key → `secret.sh put s3-admin-access-key` and `-secret-key` → `source scripts/env.sh && scripts/bootstrap.sh` (state bucket policy) → deploy → delete the old key |
| Registry push token | new token → `secret.sh put registry-push-token` → `secret.sh gitea registry-push-token REGISTRY_TOKEN` → delete the old one |
| Pulumi passphrase | `pulumi stack change-secrets-provider passphrase` per stack with the new one, then `secret.sh put pulumi-passphrase` |
| Node SSH key | new key → `watchtower:sshPublicKey` and `/root/.ssh/authorized_keys` on every node → `secret.sh put ssh-private-key` |

Old versions stay in Secret Manager's history until destroyed:
`gcloud secrets versions destroy <n> --secret <id> --project watchtower-observe`.

## Released volumes

The storage class keeps volumes when their claims go (`reclaimPolicy:
Retain`), so no deploy can delete telemetry WALs or Grafana's database. A
deleted claim leaves a `Released` PersistentVolume and a billed Hetzner
Volume:

```bash
kubectl get pv | grep Released
kubectl delete pv <name>         # then delete the volume in the Console
```

## Common issues

| Symptom | Likely cause | Fix |
|---|---|---|
| Deploy stops at "Destructive changes to guarded resources" | The preview would replace a node, IP, bucket, volume or namespace | Read the listed URNs; if intended, dispatch with `allow_replace=true` |
| Deploy fails "kube_version changed" | Kubernetes upgrade pushed | Dispatch with `kubespray=upgrade` |
| Ansible "Host key verification failed" | `known_hosts` stale or missing | Re-export `knownHosts` from the cloud stack |
| Peers connect but get no handshake | Floating IP on the wrong node | See "The Floating IP" |
| Caddy has no certificate | DNS-01 failing | `kubectl -n watchtower-edge logs deploy/edge -c caddy`; check the key and that the zone is delegated |
| A node drops traffic it should accept | The address isn't in the lists the ruleset mirrors | `journalctl -k -g nft-drop` on the node; fix the cloud stack's CIDR config and merge; every deploy renders the ruleset again |
| Pods blocked by SELinux | A workload needs host access it wasn't given | `ausearch -m avc -ts recent` on the node; do not switch SELinux to permissive — fix the pod's `seLinuxOptions` |
| Loki "no org id" | Client without `X-Scope-OrgID` | Fix the Alloy config |
| Ingester PVC pending | hcloud-csi or its token | `kubectl -n kube-system logs deploy/hcloud-csi-controller` |

## Cost

Roughly three times the old single CPX42: three CPX42 nodes, about 250 GB of
volumes, three primary IPv4s, one Floating IPv4, and Hetzner Object Storage
(base fee plus usage). No load balancers. Cloud DNS costs cents.
