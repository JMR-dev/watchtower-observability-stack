# Runbook

## Day-to-day operations

### Start / stop services

```bash
systemctl start mimir loki tempo grafana
systemctl stop  mimir loki tempo grafana
systemctl status mimir
journalctl -u mimir -f
```

### Reload config

After editing a config template:

```bash
ansible-playbook ansible/playbooks/deploy.yml --ask-vault-pass
```

The handler restarts only services whose config changed.

### View logs

```bash
journalctl -u loki --since '1 hour ago'
podman logs -f loki
```

## WireGuard

### Add a peer

1. Peer generates a key pair: `wg genkey | tee priv | wg pubkey > pub`.
2. Add to `ansible/group_vars/all/vault.yml` (vault-encrypted):
   ```yaml
   vault_wireguard_peers:
     - name: alice-laptop
       public_key: <CONTENTS_OF_PUB>
       allowed_ips: 10.8.0.11/32
   ```
3. `ansible-playbook playbooks/site.yml --tags wireguard --ask-vault-pass`
4. Send peer their config (including server public key + endpoint).

### Revoke a peer

1. Remove the peer block from vault.
2. Re-run the wireguard role.
3. Live revocation: `wg set wg0 peer <PUB> remove`.

## GDPR right to erasure

```bash
ansible-playbook ansible/playbooks/gdpr-purge.yml \
  -e tenant=team-alpha \
  -e 'selector={user_id="abc-123"}' \
  -e start=2025-01-01T00:00:00Z \
  --ask-vault-pass
```

The Loki compactor processes deletes after `retention_delete_delay = 2h`.
Confirm completion via:

```bash
curl -H 'X-Scope-OrgID: team-alpha' \
     'http://10.8.0.1:3100/loki/api/v1/delete'
```

Audit log: `/var/log/observability/gdpr-audit.log`.

## Breach response

1. **Detect** — alert from Grafana audit log or Hetzner abuse notice.
2. **Contain** — block the affected WireGuard peer, rotate Hetzner Object
   Storage credentials (Cloud Console → Security → Generate new keys), update
   `vault.yml`, redeploy.
3. **Assess** — what tenant, what data, what window. Use Grafana audit log
   and journald for forensics.
4. **Notify** — within 72 hours notify **BayLDA**
   (https://www.lda.bayern.de/). If high risk to data subjects, notify them
   directly per Art. 34.
5. **Document** — append to `/var/log/observability/breach-log.md`.

## Recovery / DR

- All telemetry is reproducible from clients — no need to back up local WAL.
- Grafana DB (dashboards, users, orgs): nightly export via
  `scripts/backup-grafana.sh` to S3 (`watchtower-grafana-backup`).
- OpenTofu state: versioned in Cloudflare R2 with object versioning enabled.
- Server replacement procedure:
  1. `tofu apply -replace=hcloud_server.watchtower`
  2. `ansible-playbook playbooks/site.yml`
  3. Restore Grafana DB from backup.
  4. Buckets are unchanged → telemetry resumes ingesting.

## Common issues

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Service won't start, `cannot assign requested address` | wg0 not up | `systemctl status wg-quick@wg0`; restart |
| Mimir 403 from S3 | bad keys in `s3.env` | regenerate Hetzner keys, redeploy |
| Loki "no org id" | client missing X-Scope-OrgID header | check Alloy config |
| LUKS volume not mounted after reboot | keyfile missing | check `/root/observability.luks.key` exists, re-run luks role |
| Grafana login redirects loop | cookie_secure=true behind plain HTTP | leave cookie_secure=false (VPN provides encryption) |

## Host firewall (nftables)

### Inspect ruleset
```bash
# Watchtower's own table:
nft list table inet watchtower

# Everything (includes fail2ban's table inet f2b-table and Podman's tables):
nft list ruleset
```

### Reload after editing
The ruleset is rendered to `/etc/nftables/watchtower.nft` and loaded via
`/etc/sysconfig/nftables.conf`.

```bash
# Validate before applying:
nft --check --file /etc/nftables/watchtower.nft

# Apply:
systemctl reload nftables   # or: systemctl restart nftables
```

### Drop counters / log
Drops are logged at `info` level (rate-limited 5/min) with prefix `nft-drop-input:`.

```bash
journalctl -k --since '1 hour ago' | grep nft-drop-input
nft list table inet watchtower | grep counter
```

### Adjust admin allow lists
Edit `ansible/group_vars/all/main.yml` (`admin_allow_ipv4`, `admin_allow_ipv6`) and
re-run `ansible-playbook ansible/playbooks/site.yml --tags firewall` (or just rerun
the whole site playbook).

## fail2ban

### Status
```bash
fail2ban-client status              # list of active jails
fail2ban-client status sshd         # per-jail: banned IPs, totals
fail2ban-client status recidive
```

### Unban an IP
```bash
fail2ban-client set sshd unbanip 203.0.113.42
fail2ban-client set recidive unbanip 203.0.113.42
```

### Inspect bans at the kernel level
fail2ban uses its own nftables table — bans are sets inside `inet f2b-table`:

```bash
nft list table inet f2b-table
```

### Logs
```bash
tail -f /var/log/fail2ban.log
journalctl -u fail2ban -f
```

### Tuning
Defaults live in `ansible/roles/fail2ban/defaults/main.yml`. Override in
`group_vars/all/main.yml` — e.g. shorten `fail2ban_findtime`, raise
`fail2ban_maxretry`, or extend `fail2ban_recidive_bantime`.

## Automatic security updates

Configured via `dnf-automatic` (`roles/base`):

- **Scope**: `upgrade_type = security` only — feature/major version bumps are not auto-applied.
- **Apply + reboot**: `apply_updates = yes`, `reboot = when-needed` (kernel/glibc/systemd
  triggers `shutdown -r +5`).
- **Schedule**: `dnf-automatic-install.timer`, pinned via drop-in to `01:00 America/Chicago` (follows CST/CDT automatically)
  with up to 30m random delay.
- **Excluded packages** (operator applies these manually): `podman*`, `conmon`,
  `crun`, `containers-common`, `netavark`, `aardvark-dns`, `container-selinux` —
  upgrading these mid-day would restart the observability stack.

### Inspect
```bash
systemctl list-timers dnf-automatic-install.timer
systemctl status dnf-automatic-install.service
journalctl -u dnf-automatic-install.service --since '2 days ago'
dnf updateinfo list security        # what's pending
dnf needs-restarting -r             # is a reboot needed?
```

### Run on demand
```bash
systemctl start dnf-automatic-install.service
```

### Update the excluded container packages (manual)
Schedule a maintenance window, then:
```bash
dnf -y upgrade podman conmon crun containers-common netavark aardvark-dns container-selinux
systemctl restart mimir loki tempo grafana
```

### Disable temporarily
```bash
systemctl disable --now dnf-automatic-install.timer
```
