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

   **Healthchecks.io**, project `jasonmross.dev`:
   - an API key (read-write), for `scripts/healthchecks.sh`;
   - one check for the nightly backup of Grafana's database: schedule Cron
     `30 2 * * *` in UTC, grace 1 hour, with the project's notifications
     (ours is named `healthchecks-pg-backup-url`). Copy its ping URL.
2. **Store every secret.** Paste each token or key at the hidden prompt;
   generate the rest:
   ```bash
   scripts/secret.sh put hcloud-token
   scripts/secret.sh put healthchecks-pg-backup-url
   scripts/secret.sh put healthchecks-jasonmross-dev-api-key
   scripts/healthchecks.sh   # a check per host, one for the deploy, one for the bastion; stores their ping URLs
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
   (`watchtower-root.pub`). Commit it. Bootstrap (next) adds
   `breakGlassCidrs` and `bastionHostKey`: the bastion is the only public
   SSH source, to the proxy.
4. **Bootstrap** (state bucket, DNS zone and delegation, service accounts,
   the image registry, the secrets' access grants), then the four GCP keys:
   ```bash
   source scripts/env.sh
   scripts/bootstrap.sh                      # a new bastion: confirm its ruleset by hand when it asks (below)
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
   `images (wg-easy)`, `semgrep`, `shell`, `alloy`.
7. **First deploy, through the bastion.** The deploy reaches the hosts over
   the VPN as its own peer, which the first deploy creates. So, from scratch,
   dispatch `deploy.yml` with `ssh_via=bastion` (Actions → deploy → Run
   workflow); a plain push would stop at "No deploy VPN peer yet". It builds our images, creates the hosts,
   installs everything (all three nodes at once the first time), and
   verifies it end to end.
8. **Your VPN peer.** The deploy created the wg-easy client `owner` and
   added its config to the secret `wireguard-owner-peer`
   (`ansible/roles/edge/tasks/peer.yml`). Fetch it and import it:
   ```bash
   scripts/secret.sh pull wireguard-owner-peer
   gopass show -n watchtower/wireguard-owner-peer >watchtower.conf
   nmcli connection import type wireguard file watchtower.conf && shred -u watchtower.conf
   nmcli connection up watchtower
   ssh root@10.8.0.1           # the proxy, over the tunnel
   ```
   The tunnel is split: only 10.8.0.0/24 goes through it, and your own DNS
   stays as it is. More peers come from the UI on
   `https://watchtower.jasonmross.dev:51821` (user `admin`, the wg-easy
   password).
9. Open `https://watchtower.jasonmross.dev` (Grafana, user `admin`) and point
   a test Alloy (`config/alloy/config.alloy.example`) at the stack.

## Host access

SSH is only for WireGuard peers, the deploy, and break glass:

| From | To | Path |
|---|---|---|
| A VPN peer (you) | the proxy | `10.8.0.1`, over the tunnel |
| The deploy | the proxy | `10.8.0.1`, as its own VPN peer (`wireguard-deploy-peer`) through wireproxy (`scripts/vpn-tunnel.sh`) |
| The break-glass bastion (`breakGlassCidrs`) | the proxy | its public address, the bastion reached through IAP; also the deploy's, dispatched with `ssh_via=bastion` |
| Any of those | a node | through the proxy, to the node's private address |

The nodes take nothing on their public addresses, and only the proxy's
private address may reach their SSH.

`scripts/ssh-config.sh vpn|bastion` writes
`ansible/inventory/ssh_config`, which picks the way to the proxy and jumps
from it to the nodes, with the pinned host keys. Ansible (`ansible.cfg`),
`scripts/verify.sh` and you all go through it, by inventory name:

```bash
source scripts/env.sh       # the key, as ANSIBLE_PRIVATE_KEY_FILE and in ssh-agent
(cd infra/cloud && pulumi stack output inventory >../../ansible/inventory/hosts.yml \
  && pulumi stack output knownHosts >../../ansible/inventory/known_hosts)
scripts/ssh-config.sh vpn                          # from a WireGuard peer
(cd ansible && ansible all -m ping)
ssh -F ansible/inventory/ssh_config watchtower-proxy
ssh -F ansible/inventory/ssh_config watchtower-2
scripts/verify.sh <archive-bucket>
```

### Break glass: the bastion

When the VPN is down, use the bastion:

```bash
scripts/ssh-config.sh bastion        # IAP + OS Login as your gcloud account, a key valid for 4 hours
ssh -F ansible/inventory/ssh_config watchtower-proxy
```

- **What it is:** `watchtower-bastion`, an e2-micro in us-east1-b, the free
  tier.
  - It has no external address.
  - Its SSH is open only to IAP (35.235.240.0/20), with OS Login.
  - Its traffic leaves through Cloud NAT from the one address in
    `breakGlassCidrs`, the only public SSH source the proxy admits.
  - It installs security updates daily and reboots at 04:00 UTC when one
    needs it.
  - It pings its Healthchecks.io check, `watchtower-bastion`, after each boot and
    at 05:00 UTC every day, once its guard is verified loaded and sshd is active.
    One that didn't come back from a reboot, or is up without either, emails by
    07:00. The daily ping is there because the reboot comes only when an update
    needs it, and a check pinged only at boot would have nothing to go overdue by.
    The ping URL is a secret, `healthchecks-bastion-url`, which root reads with
    the VM's token and hands to curl on stdin. A failed ping logs one line and
    touches nothing else.
  - It runs as `watchtower-bastion@`, which may read its own agent peer
    (`wireguard-bastion-peer`) and that ping URL and nothing else, and ships its
    journal and metrics to watchtower through `wg-watchtower`
    (docs/client-telemetry.md).
    Until its guard's ruleset is confirmed (below), it runs as no one and
    ships nothing. Only a missing or empty `wireguard-bastion-peer` takes that
    down: any other failure to read it warns and leaves the tunnel and Alloy
    as they are. To revoke the bastion's peer, delete its client in wg-easy.
  - Only root may reach the metadata server, and with it the VM's token:
    nftables (`config/bastion/nftables.conf`) refuses every other uid but
    for DNS, DHCP and NTP. `nft list chain inet metadata_guard metadata`
    counts the refusals. A restart of `nftables.service` reloads and never
    flushes it (a drop-in clears `ExecStop`). A ruleset that won't load at a
    boot brings a small copy of the guard built into the tool, the floor,
    before the network comes up.
  - sshd runs only with the guard in the kernel, or on a VM with no account
    and so no token: `watchtower-ruleset gate`, before every start. A package
    upgrade of either leaves both running. Nothing of a user's runs without a
    login, so nothing gets past that gate: cron and at are root's, polkit
    refuses lingering, and any crontab or linger file from before is removed
    at every boot.
  - Its startup script (`config/bastion/startup.sh`) sets all of this up
    at every boot; its output is in `journalctl -u google-startup-scripts`
    and on the serial console, and never holds the peer config or the ping URL.
- **Who may use it:** you (project owner), and `watchtower-deployer`, which
  has OS Login on that VM and an IAP tunnel to its port 22, nothing more.
  The deploy uses it when dispatched with `ssh_via=bastion`: when wg-easy
  is down, the proxy is being rebuilt, or the environment is new. OS Login
  admits a user to a VM that runs as a service account only if they may act
  as it, so bootstrap gives the deployer `roles/iam.serviceAccountUser` on
  `watchtower-bastion@`. The guard is what keeps it from the VM's token.
- **Rebuilding it:**
  - `scripts/bootstrap.sh` (step 7) makes the bastion, and writes its NAT
    address and SSH host key into `infra/cloud/Pulumi.prod.yaml`
    (`breakGlassCidrs`, `bastionHostKey`).
  - A change to `config/bastion/` or `config/alloy/bastion.alloy` reaches
    it when you rerun bootstrap: it stops the bastion, sets its metadata,
    and starts it again. The boot disk, and with it the host key, stays;
    anyone on the bastion then is cut off.
  - The first time, or on a new bastion, that takes two restarts: bootstrap
    attaches the account only once this boot has confirmed its ruleset (below)
    and finished apt, and asks again of the boot with the account, so don't run
    it during a deploy with `ssh_via=bastion`. Bootstrap goes by guest attributes
    (`watchtower/ruleset`, `watchtower/settled`), which the guard keeps from
    every uid but root, and never by the serial console, where any user can put
    a line. On a VM with no guard yet a user could write them too, which is why
    it asks again.
  - If a run fails between a stop and its start (no capacity in the zone, a
    lost connection), the bastion stays stopped and break glass is down.
    Rerun bootstrap, which starts a stopped bastion first, or
    `gcloud compute instances start watchtower-bastion --zone us-east1-b`.
  - To replace it: `gcloud compute instances delete watchtower-bastion
    --zone us-east1-b`, rerun bootstrap, commit `Pulumi.prod.yaml`, and
    deploy. The NAT address is reserved and stays; the host key changes.
- **A new ruleset** (`config/bastion/ruleset.sh`): one that locked everyone
  out would strand break glass, so a new one undoes itself.
  - The boot that finds it in metadata loads it first in a network namespace of
    its own, where nothing can see it. Then it keeps the old file, records the
    trial on disk, arms a 10-minute timer, and installs and loads it. A reboot
    in those 10 minutes starts them again.
  - Any login cancels it, no sudo needed: an interactive shell does so by
    itself, or `touch /run/watchtower-ruleset/confirm`. A login from before the
    load doesn't count. Bootstrap dispatches `bastion-confirm.yml` for the branch
    it's run from, which logs in as the deployer over IAP, and waits for
    `confirmed` in the guest attribute. The account goes on only after that, and
    bootstrap reports success only if the boot it ends on has said `confirmed`.
  - No login in time: `rolled back`, the old file back, the new one's sha256
    recorded as rejected so the next boot leaves it alone, and a reboot. Bootstrap
    stops there, with the VM on the old ruleset and, if it has no account yet,
    running as no one. It says so again at every boot while metadata holds that
    file.
  - **Gitea down, or the dispatch fails:** bootstrap says so. It prints the
    command to confirm by hand whenever a ruleset goes pending, which any account
    with OS Login on the VM may run. Otherwise the rollback is what happens.
  - **To recover, rerun bootstrap.** A fixed file has a new sha256 and is tried
    afresh. The same file is tried again too, since nothing need be wrong with
    it: bootstrap asks for it once more (`watchtower-nftables-retry` in
    metadata).
  - **A file that won't load, or gives no hooked guard,** never goes on, whatever
    its comments say: `refused`, what runs now stays, and bootstrap stops, on a
    rerun too.
  - **A first install** has no old ruleset, and the VM has no account yet, so
    no token to guard. Rollback puts back the package's empty ruleset, and sshd
    still runs, on the floor, so break glass stays up. A new environment's first
    run has no `GCP_DEPLOYER_KEY` yet (`rotate-gcp-key.sh deployer` comes after
    bootstrap), so the job can't log in: confirm by hand when bootstrap prints how.
  - **A rollback the disk won't take** (`failed`, on a full or read-only disk):
    the old ruleset goes into the kernel at once, and that needs no disk, so sshd
    keeps running on it. The trial's file stays on disk with its record, nothing
    new goes on, and the rollback retries every minute with no reboot, then
    reboots once it works. A login can't confirm it now. A fixed file in metadata
    can't help, as it needs the same disk. The way in is a startup script that frees
    the disk: "The bastion with SSH gone", below.
  - **The guard won't load at a boot with no change:** `failed`, and bootstrap
    stops. The floor came on before the network, or the startup script loads the
    old ruleset into the kernel, and sshd starts on that, so the VM stays guarded
    and reachable. A file that has stopped loading never becomes the old ruleset:
    the last one that loaded stays the way back. The next boot tries the current
    file again.
  - **nft loads nothing at all, not even the floor,** on a VM with an account:
    sshd stays down, since nothing may run with a token and no guard. The way back
    is new metadata: rerun bootstrap with a ruleset that loads, or "The bastion
    with SSH gone", below, which also says why it's down. The serial console only
    reads.

Every service is a quadlet: `/etc/containers/systemd/<name>.container`
generates `<name>.service`.

```bash
systemctl status loki mimir kafka etcd patroni grafana 'tempo-*'
journalctl -u loki -f                   # every container logs to the journal
podman ps
```

Change a service through its role and a deploy, never by hand: the next
deploy would put it back.

### The bastion with SSH gone

New metadata is the way in. The serial console is for reading only: the bastion
has only OS Login users and no local password, so a console's login prompt has
no credential to accept, and it isn't getting one. A startup script needs no
login: GCE runs it as root at the next boot, and `gcloud` can put it there and
reset the VM with no SSH at all. `config/bastion/recovery.sh` is that script, kept
fixed and ready. It frees the disk if it's full, asks for sshd and says where
everything ended up.

**Written by reading the code, and not yet tried on the real VM.** Try it once
during the first rollout ("To try it", below), then remove this line.

Run these from a checkout of what the bastion last got from bootstrap.

1. **Put the script in metadata and reset.** This replaces `startup-script` and no
   other key. The reset is immediate; the disk and host key stay, and anyone on
   the bastion is cut off.
   ```bash
   gcloud compute instances add-metadata watchtower-bastion --zone us-east1-b --project watchtower-observe \
     --metadata-from-file startup-script=config/bastion/recovery.sh
   gcloud compute instances reset watchtower-bastion --zone us-east1-b --project watchtower-observe
   ```
   The guard and the gate don't depend on the startup script: their units are on
   disk, so that boot loads the guard and asks the gate as any other does.
2. **Read what it says,** a minute or two after the reset. This needs no login and
   no `serial-port-enable`. The output keeps earlier boots, so read from the last
   `start:` line.
   ```bash
   gcloud compute instances get-serial-port-output watchtower-bastion --zone us-east1-b --project watchtower-observe --port 1 |
     grep 'bastion-recovery:'
   ```
   With nothing full, you should see:
   ```
   bastion-recovery: start: 2026-11-02 04:10:11 UTC
   bastion-recovery: disk: 41% of / used, 9% of its inodes
   bastion-recovery: not full: removing nothing
   bastion-recovery: guard: loaded
   bastion-recovery: sshd: active
   bastion-recovery: disk: 41% of / used, 9% of its inodes
   bastion-recovery: done
   ```
3. **Log in.** That is the proof: anyone on the VM can put a line on the console,
   though the reset has just put them out.
   ```bash
   gcloud compute ssh watchtower-bastion --zone us-east1-b --project watchtower-observe --tunnel-through-iap
   sudo journalctl -b -u nftables -u ssh -u google-startup-scripts   # what happened
   ```
4. **Put the normal startup script back.** Until you do, every boot runs the fixed
   script instead: harmless, but no new ruleset, peer or Alloy config reaches the
   VM. What's running keeps running, and the daily ping goes on, from its copy on
   disk.
   ```bash
   gcloud compute instances add-metadata watchtower-bastion --zone us-east1-b --project watchtower-observe \
     --metadata-from-file startup-script=config/bastion/startup.sh
   gcloud compute instances reset watchtower-bastion --zone us-east1-b --project watchtower-observe
   gcloud compute instances get-guest-attributes watchtower-bastion --zone us-east1-b --project watchtower-observe \
     --query-path watchtower/ruleset
   ```
   The attribute should say `confirmed`, with the sha256 of
   `config/bastion/nftables.conf` and a time after the reset. The console should say
   `bastion: pinged the Healthchecks.io check`. Or rerun bootstrap instead of those
   commands: it sees the metadata differ, stops the VM, sets it, starts it and waits
   for that word itself. After a rollback, rerun bootstrap either way: it's what
   asks for the rejected file again.

**A full disk** (`failed` in the guest attribute, "A rollback the disk won't take"
above, or logins failing for want of room): the same four steps. Over 90% used, in
blocks or inodes, the script empties apt's cache, old rotated logs and the journal
past 64M, and says so:

```
bastion-recovery: disk: 100% of / used, 12% of its inodes
bastion-recovery: over 90%: emptying apt's cache, old rotated logs and the journal past 64M
bastion-recovery: disk: 58% of / used, 11% of its inodes
```

- **If a rollback was stuck,** it now finishes and the VM reboots:
  `bastion: ruleset rolled back <sha256> at <epoch>`, then
  `a rollback finished: rebooting, and this script runs once more`, and a second
  run from `start:` to `done`. The rollback's own retry may get there first, and
  then that second run comes without those two lines. Then step 3, step 4, and rerun
  bootstrap.
- **Still over 90%:** Alloy's buffer goes next, so what it hadn't shipped is lost,
  and then the script lists the largest paths. It never removes a user's files.
  Copy it, add a line that removes what you've read there, at the top of `main`,
  and repeat from step 1 with the copy.
- **No `bastion-recovery:` line at all after 5 minutes:** the guest agent writes the
  script to disk before running it, so a disk with not a byte free may never run
  it. Grow the disk, which needs no room on it and can't be undone (the free tier
  covers 30 GB of standard disk), then read on from step 2. Debian's GCE image
  should grow its root filesystem to fit at boot, and the `disk:` lines will show
  whether it did; this is the least proven line here.
  ```bash
  gcloud compute disks resize watchtower-bastion --zone us-east1-b --project watchtower-observe --size 20GB
  gcloud compute instances reset watchtower-bastion --zone us-east1-b --project watchtower-observe
  ```

**`sshd: NOT active`:** the lines under `why sshd isn't up:` hold `sshd -t` and the
journal of `nftables` and `ssh`. The script has already reinstalled nftables once.
For anything else, add the fix to a copy of the script and repeat from step 1. If it
is `guard: NOT loaded`, because nft loads nothing at all, take the account off: on a
VM with no token there's nothing to guard, so the gate lets sshd run. The tunnel and
Alloy stay as they are, and the ping stops, so its check goes overdue. Once it's
fixed, step 4 and a rerun of bootstrap, which attaches the account again over a
confirmed ruleset.

```bash
gcloud compute instances stop watchtower-bastion --zone us-east1-b --project watchtower-observe
gcloud compute instances set-service-account watchtower-bastion --zone us-east1-b --project watchtower-observe --no-service-account --no-scopes
gcloud compute instances start watchtower-bastion --zone us-east1-b --project watchtower-observe
```

**To try it,** once, during the first rollout: after bootstrap has reported `Done`
with the account attached, and not during a deploy with `ssh_via=bastion`, run steps
1 to 4 on the healthy bastion. It should say `not full: removing nothing`, let you
log in, and come back to `confirmed` and a ping. Then remove the "not yet tried"
line above.

## WireGuard peers

Peers are managed in the wg-easy UI at `https://watchtower.jasonmross.dev:51821`
(from a peer). Each client config points at `vpn.watchtower.jasonmross.dev`
(the proxy) and routes only 10.8.0.0/24. Revoke a peer by disabling or
deleting it in the UI; it takes effect at once.

The tunnel range has two halves:

- **Admin peers, 10.8.0.0/25:** the owner's, the deploy's, and any peer made
  in the UI (wg-easy numbers from the bottom). They reach every listener on
  10.8.0.1: Grafana, the query APIs, wg-easy's UI and SSH.
- **Agent peers, 10.8.0.128/25:** one per service that ships telemetry here
  (`names.AgentPeers`; docs/client-telemetry.md). The deploy creates each,
  moves it to its fixed address with a keepalive and an MTU of 1380, and
  adds its config to `wireguard-<peer>-peer`. Every deploy also resets an
  agent's hooks, DNS and routes, so a change made to one in the UI is
  undone: its config runs as root on someone else's server. The firewall lets them reach
  only Caddy's ingest listeners (3100, 8080, 4317, 4318), and Caddy only the
  write paths, putting everything in the tenant `jasonmross` whatever they
  ask for; anything else is 403.

Never move a person's peer into the agent half, or an agent's out of it.

**Rekey an agent peer:** delete its client in the UI. The next deploy makes
a new one and publishes it; each service picks it up on its next deploy or
boot (Vaultwarden only on a dispatch; the bastion at boot, or at once with
`sudo google_metadata_script_runner startup` on it). Then
`scripts/secret.sh pull wireguard-<peer>-peer` for the gopass copy.

**Check the gating** after any change to it, from a host that is an agent
peer (each must fail as shown, and a line pushed with any tenant must
arrive in `jasonmross`):

```bash
d=https://watchtower.jasonmross.dev
curl -s -o /dev/null -w '%{http_code}\n' $d:3100/loki/api/v1/labels                      # 403
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$d:3100/loki/api/v1/delete?query=x"    # 403
curl -s -o /dev/null -w '%{http_code}\n' "$d:8080/prometheus/api/v1/query?query=up"      # 403
curl -s -o /dev/null -w '%{http_code}\n' $d:8080/prometheus/config/v1/rules              # 403
curl -s -o /dev/null -w '%{http_code}\n' $d:8080/alertmanager/api/v2/status              # 403
for port in 22 443 3200 51821; do timeout 5 bash -c "</dev/tcp/10.8.0.1/$port" && echo "$port OPEN"; done
# nothing printed
```

On the proxy, `nft list table inet watchtower` shows the agents' drop
counter, and `journalctl -k -g nft-agent-drop` what it dropped (sampled).

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
mirrors the Hetzner Cloud Firewalls from the same `breakGlassCidrs` and
`wireguardAllowCidrs`. SSH: on the proxy from WireGuard admin peers (the
deploy among them) on the tunnel address and from the bastion on its public
one (agent peers reach only the ingest listeners);
on a node only from the proxy's
private address. On the mesh (wg1), nodes reach each other fully and the
proxy only the ports Caddy proxies to. Kafka, etcd, Patroni and
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
that comes back behind is rewound by Patroni (`pg_rewind`, as `postgres`). One
it can't rewind stays in `start failed`, and every deploy stops at it, until
you reclone it from the leader:

```bash
podman exec patroni patronictl -c /etc/patroni/patroni.yml reinit watchtower <node> --force
```

## Grafana database backups

Patroni's replicas survive a lost node, not a mistake: a deleted dashboard,
a bad Grafana upgrade or a lost LUKS key reaches every copy at once. So
every night at 02:30 UTC the Postgres leader dumps the `grafana` database
(`pg_dump --format=custom`) to
`s3://jmr-watchtower-postgres-backups/grafana/grafana-<UTC time>.dump`
(`ansible/roles/pgbackup`). The bucket's lifecycle rule deletes each dump
after 90 days. The servers' cluster key can only add dumps; reading,
listing and deleting them takes the admin key.

- **Alerts** come from the Healthchecks.io check behind
  `healthchecks-pg-backup-url`:
  - a failed run reports to it at once, with its log (`OnFailure=`);
  - a night without a successful run alerts once the check's grace runs
    out;
  - a run also fails, and alerts, when no Patroni member reports a leader,
    since then no node would back up.
- **A backup now:** `systemctl start watchtower-pg-backup` on every node.
  Replicas exit; the leader dumps. Every deploy's verify step does this.
- **Logs:** `journalctl -u watchtower-pg-backup` on the node.

### Restoring

1. Fetch a dump with the admin key:
   ```bash
   source scripts/env.sh
   s3() { aws --endpoint-url https://fsn1.your-objectstorage.com --region fsn1 "$@"; }
   s3 s3 ls s3://jmr-watchtower-postgres-backups/grafana/ | tail
   s3 s3 cp s3://jmr-watchtower-postgres-backups/grafana/grafana-<time>.dump ./grafana.dump
   ```
2. Stop all three Grafanas, so nothing writes during the restore:
   `systemctl stop grafana` on every node.
3. Restore on the leader (`patronictl list` names it; `<leader>` is its
   private address, 10.20.1.1<n>). The replicas follow
   by streaming replication:
   ```bash
   ssh -J root@10.8.0.1 root@<leader> podman exec -i patroni \
     pg_restore --clean --if-exists --single-transaction --dbname=grafana <grafana.dump
   ```
4. `systemctl start grafana` on every node, then check the UI.

To get back one dashboard rather than everything, restore into a scratch
database on the leader instead, with Grafana left running:
```bash
ssh -J root@10.8.0.1 root@<leader> podman exec patroni createdb grafana_restore
ssh -J root@10.8.0.1 root@<leader> podman exec -i patroni pg_restore --dbname=grafana_restore <grafana.dump
```
Copy the dashboard's JSON out of its `dashboard` table, import it in
Grafana, then `podman exec patroni dropdb grafana_restore`.

A dump is only usable with the `grafana-secret-key` in force when it was
made: Grafana encrypts datasource secrets with it.

## Host health

High availability hides a lost node from users, so each host reports on
itself instead (`ansible/roles/health`). Every 5 minutes
`watchtower-health.timer` checks that:
- every service on the host is active: each quadlet, plus WireGuard, the
  firewall, fail2ban and the update, reboot and backup timers;
- each service on a node answers ready: Loki, Mimir, every Tempo
  component, Grafana, Patroni and etcd, and Kafka takes connections. On the
  proxy, Caddy answers TLS for the domain on the tunnel address;
- SELinux is enforcing, the data volume is mounted, and `/` and the
  volume are under 90% full.

It reports to the host's own Healthchecks.io check (`watchtower-proxy`,
`watchtower-1`, ...; project `jasonmross.dev`), which emails:
- **two unhealthy runs in a row** (5 to 10 minutes): `/fail`, with the
  problems. A single bad run is only logged on the check, since a deploy
  restarts services;
- **no report for 15 minutes**: the host is down, cut off, or its timer
  is dead.

`scripts/healthchecks.sh` creates the checks (one per host from
`nodeCount`; re-run it after changing that) and stores their ping URLs as
`healthchecks-host-urls`. The deploy gives each host only its own URL. The
same script creates `watchtower-deploy` (see "Our images") and
`watchtower-bastion` ("Break glass"), whose URL only the bastion reads.
On a host, `watchtower-health check` prints what it sees now, without
reporting. Every deploy's verify step runs it on each host.

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

## Our images

`build/<name>/` holds each of our images: Caddy and wg-easy on Alpine,
Patroni on the Postgres image. An Alpine image's tag is its version, the
Alpine release, its revision and the day it was built, e.g.
`15.5.0-alpine3.24.3-r2-20261025`. Patroni's tag is just version and
revision, e.g. `4.1.5-r1` (`scripts/image-tag.sh <name>`). Tags in
Artifact Registry are immutable, and the deploy reuses a tag that's
already there instead of rebuilding it.

- **Rebuilt every day but Sunday.** `deploy.yml` also runs at 05:00 UTC,
  Monday to Saturday. Sunday is the hosts' reboot morning (from 07:00).
  - The guard job fixes the run's inputs once (`image-tag.sh --inputs`):
    the newest patch release of the Alpine minor the Dockerfiles name
    (`ARG ALPINE=docker.io/library/alpine:3.24`), and the day.
  - The day's first deploy builds every Alpine image on that release, by
    digest, with `apk upgrade`, so each package is the day's. It rolls them
    out one host at a time behind the health gate.
  - Deploys later that day reuse the morning's builds. The images on the
    hosts are at most a day behind Alpine's package fixes, two over Sunday.
  - When Alpine ships 3.24.4, the next run builds `…-alpine3.24.4-…`.
- **The run alerts.** Every deploy ends by pinging the Healthchecks.io check
  `watchtower-deploy`. It sends `/fail` as soon as any job failed, which
  emails at once. A scheduled run that hasn't reported by 07:00 UTC emails
  too. The ping links the run.
- **Any other change needs a new tag.** If you change anything under
  `build/<name>/` without a new version (`org.opencontainers.image.version`),
  bump `watchtower.image.revision`; set it back to 1 with a new version.
  CI's `images` jobs fail a pull request that changes an image but keeps its
  tag. Otherwise a deploy later that day, or any deploy of Patroni, would
  keep serving the old image under it.
- **A new Alpine minor** (3.25): change `ARG ALPINE` in every Dockerfile
  together; `image-tag.sh` refuses a mix.
- **Building one locally:** `scripts/build-image.sh <name> <ref>` (docker;
  render the configs first with `ansible/playbooks/render.yml`). It builds,
  checks and scans the image just as CI does.

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

**Rebuilding the proxy** takes the VPN down with it, the deploy's way in
included. Dispatch with `ssh_via=bastion` too: the deploy goes through the
bastion, reinstalls the proxy, and wg-easy comes back from its database on
the data volume with every peer, the deploy's own among them.

## Log archive

```bash
aws --endpoint-url https://fsn1.your-objectstorage.com --region fsn1 \
  s3 ls s3://jmr-watchtower-logs-archive/containers/$(date -u +%Y/%m/%d)/ --recursive
aws --endpoint-url https://fsn1.your-objectstorage.com --region fsn1 \
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
| Backup check's ping URL | a new check → `secret.sh put healthchecks-pg-backup-url` → deploy → delete the old check |
| Healthchecks.io API key | a new key in the project's settings → `secret.sh put healthchecks-jasonmross-dev-api-key` → revoke the old one (only `scripts/healthchecks.sh` uses it) |
| Hosts' ping URLs | delete a host's check, `scripts/healthchecks.sh` (it makes a new one), then deploy |
| The bastion's ping URL | delete its check, `scripts/healthchecks.sh` (it makes a new one and stores the URL); the bastion reads it at its next boot or daily ping |
| Agent peers' WireGuard keys | delete the client in the wg-easy UI, then deploy ("WireGuard peers") |

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
| Deploy: `S3Bucket ... expected non-nil error with nil state during Create` | Hetzner created the bucket, but it didn't show yet when the provider read it back, so Pulumi never recorded it | Adopt it, then rerun: `pulumi import minio:index/s3Bucket:S3Bucket <bucket> <bucket> --provider hetzner-s3=urn:pulumi:prod::watchtower-cloud::pulumi:providers:minio::hetzner-s3 --generate-code=false` from `infra/cloud` after `source scripts/env.sh` |
| Healthchecks.io: a host's check is down | The host reported problems twice in a row, or stopped reporting (down, cut off from the internet, its timer dead) | The alert lists the problems. If it went silent: is the server up (Hetzner Console), and `systemctl status watchtower-health.timer` on it. `watchtower-health check` shows what it sees now |
| Healthchecks.io: `watchtower-deploy` is down | A deploy job failed, or the 05:00 UTC run (Monday to Saturday) never came | The ping's body links the failed run; its log says which job. If `hosts` failed with "the tunnel to 10.8.0.1:22 never came up", wg-easy or the proxy is down: dispatch with `ssh_via=bastion`, which reinstalls the proxy without the VPN. No run at all: is Gitea's scheduler running, and is `deploy.yml` on main intact? Fix, then dispatch `deploy.yml` (or merge); the next success clears it |
| Healthchecks.io: `watchtower-bastion` is down | No ping by 07:00 UTC: the bastion didn't come back from a reboot, is up without its guard or sshd, or couldn't reach Secret Manager or Healthchecks.io. A bastion you stopped does this too | `gcloud compute instances describe watchtower-bastion --zone us-east1-b --project watchtower-observe --format 'value(status)'`, then log in ("Break glass"). No login: "The bastion with SSH gone". Logged in: `sudo systemctl start watchtower-ping.service`, then `sudo journalctl -u watchtower-ping.service -n 5` says what stopped the ping |
| Healthchecks.io: the backup check is down | The nightly backup failed or never ran | The alert carries the run's log; else `journalctl -u watchtower-pg-backup -n 50` on the leader. Usual causes: a cluster S3 key replaced but not yet deployed, no Patroni leader, or the volume not mounted. `systemctl start watchtower-pg-backup` on every node retries |
| Tempo queries miss recent traces | A live-store or the Kafka path | `systemctl status 'tempo-*'` on each node; Kafka's under-replicated partitions |

## Cost

About $100 a month (USD, no VAT): three cax31 ($74.97) and one cax11
($6.99), four primary IPv4s ($2.40), 100 GB of volumes ($7.67), the Object
Storage base fee (€6.49) and a dollar or two of GCP (DNS, Secret Manager,
Artifact Registry). No load balancers, no Floating IP.
