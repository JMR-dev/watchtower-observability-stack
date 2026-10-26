# Client telemetry: our services into watchtower

Every live service of ours outside watchtower ships its logs and metrics
here, into one shared tenant. This is the contract each service's own repo
implements, and the spec for each one's change. Traces are allowed through
but off in v1: no backend emits spans, and Caddy's would carry personal data.

| Service | Host | Ships as | Change |
|---|---|---|---|
| SilverBullet | `silverbullet-vm` (silver-bullet-dev, e2-small) | agent peer + Alloy quadlet | S1, silverbullet-deployment |
| Blog | `blog-vm` (dev-blog-494815, e2-micro, 1 GB) | agent peer + Alloy quadlet | B1, dev_blog |
| Vaultwarden | `vault-production`, `vault-disposable` (vaultwarden-497422) | agent peer + Alloy host binary | V1, vaultwarden-deployment |
| Gitea CI | GKE `gitea-runners`, Cloud Run `gitea-webhook` and `build-status` | pulled from GCP by watchtower | G1, gitea (`cicd/`, `infra/`); W2, here |
| Bastion | `watchtower-bastion` (watchtower-observe, e2-micro) | agent peer + Alloy `.deb` | W3, here |
| Gitea | `gitea-vm` (gitea-496920, e2-small) | agent peer + Alloy quadlet | G2, gitea (after its Ansible cutover) |

Alerts and a fleet dashboard (W4, here) come last, for verified hosts only.

## How it fits together

- **Each VM is an agent peer:** a kernel WireGuard interface `wg-watchtower`
  with a split tunnel (10.8.0.0/24 only), at a fixed address in the agent
  half, 10.8.0.128/25. Outbound only: GCE egress is open and replies come
  back on the established connection.
- **Agents may only write.** The proxy's firewall lets them reach only
  Caddy's ingest listeners (3100, 8080, 4317, 4318); Caddy lets them use
  only the write paths, overwrites `X-Scope-OrgID` with `jasonmross`, and
  answers anything else with 403. CI checks both
  (`scripts/check-agent-gating.sh`).
- **Grafana Alloy on each host** reads the journal and the host's metrics,
  scrubs, and pushes. It is installed and configured by that service's own
  deploy, never by watchtower's.
- **Gitea CI is pulled instead:** Cloud Run has no host to put an agent on,
  the GKE base node has no headroom, and a VPN key inside the CI cluster
  would be in reach of DinD jobs. Cloud Logging sinks feed a Pub/Sub topic;
  Alloy on the watchtower nodes pulls it (and Cloud Monitoring) as
  `watchtower-gcp-reader@watchtower-observe`.

## The contract

| Item | Value |
|---|---|
| Tenant | `jasonmross`. Caddy forces it for agents; send it anyway so the config reads right |
| Loki | `https://watchtower.jasonmross.dev:3100/loki/api/v1/push` (OTLP `/otlp/v1/logs`) |
| Mimir | `https://watchtower.jasonmross.dev:8080/api/v1/push` (OTLP `/otlp/v1/metrics`) |
| Tempo | `watchtower.jasonmross.dev:4317` (gRPC), `https://watchtower.jasonmross.dev:4318/v1/traces`. Open to agents, unused in v1 |
| Agent | Grafana Alloy **v1.21.2**, pinned: an image by digest (`docker.io/grafana/alloy:v1.21.2@sha256:…`), a release zip or `.deb` by sha256 from the release's `SHA256SUMS`. No `AutoUpdate=` |
| Form | A **rootful podman quadlet** with `Network=host` on SilverBullet, the blog and the Gitea VM; a **host binary with a systemd unit** on Vaultwarden (its quadlets are rootless) and the bastion (`.deb`) |
| Memory | 2 GB hosts: 256 MiB cap (`MemoryMax=` or `PodmanArgs=--memory`), `GOMEMLIMIT=200MiB`. 1 GB hosts (blog, bastion): 192 MiB, `GOMEMLIMIT=150MiB`. An OOM then kills Alloy, not the app |
| Listeners | Alloy's UI on `127.0.0.1:12345` only. No OTLP receiver in v1 |
| State | Alloy's storage path on persistent disk (a named volume, or `StateDirectory=alloy`): the journal position and the remote-write WAL survive restarts |
| WireGuard | Interface `wg-watchtower`, unit `wg-quick@wg-watchtower`, config `/etc/wireguard/wg-watchtower.conf`, root 0600 |
| Peer config | From Secret Manager `projects/watchtower-observe/secrets/wireguard-<peer>-peer/versions/latest`, read cross-project by the one identity granted it (below). **Never printed**: no `set -x`, `no_log: true`, and nothing on boot output (the blog's and Gitea's reach Cloud Logging) |
| Peer checks | watchtower's deploy resets each agent's hooks, DNS and routes on every run and refuses to publish a config that has any; check again on the host, since the config runs there as root. Refuse the config unless it has exactly one `[Peer]` with an `Endpoint` and `AllowedIPs` exactly `10.8.0.0/24`. Refuse any `PreUp`, `PostUp`, `PreDown`, `PostDown`, `Table`, `FwMark` or `SaveConfig`. Then drop any `DNS =` line, and set `PersistentKeepalive = 25` and `MTU = 1380` if missing (watchtower sets both). A full tunnel would send the metadata server's traffic to the proxy and break the VM's credentials, image pulls and DNS-01 |
| No peer | A missing or empty secret is a warning, never a failed deploy: stop and disable the tunnel and Alloy and remove their config |
| Labels | Everything: `service`, `host`, `env` (`production`, or `disposable`). Logs also `unit`, `container`, `level`. **Never** a label from an IP, user, email, URL path, UUID or pod name |
| Metrics | `prometheus.exporter.unix` (`job="integrations/unix"`), `prometheus.exporter.self` (`job="alloy"`), Caddy's metrics (`job="caddy"`), a blackbox probe of the public health URL (`job="blackbox"`); every 60 s |
| Caddy metrics | The global `metrics` option and a site `:2020 { metrics }` bound to loopback (`bind 127.0.0.1` with host networking, `PublishPort=127.0.0.1:2020:2020` in bridge mode). **Never publish the admin API (:2019)** |
| Coraza | Its audit log goes to a **local rotated file** (`SecAuditLog /var/log/caddy/coraza-audit.log` or the like), never the journal: a record holds whole requests, cookies and bodies |
| Scrub | `config/alloy/config.alloy.example`'s `loki.process "scrub"`, plus the service's own rules (below). A fixture test in the repo's CI with `scripts/check-alloy-scrub.sh` |
| Retries | `loki.write` as in the example (`max_backoff_period = "5m"`, `max_backoff_retries = 300`, `retry_on_http_429 = true`): about a day of retrying, through a watchtower restart or the proxy's Sunday reboot |
| Units | Alloy `After=`/`Wants=wg-quick@wg-watchtower.service`, with a handler of its own. **Never** where a change restarts the app (Gitea's `vm/systemd/`, the blog's `render_all` quadlet loop) |
| Deploy check | Warn only: Alloy's `/-/ready`, then whether `wg show wg-watchtower latest-handshakes` is non-zero within 2 minutes |

### Scrubbing: what every rule must do

Nothing on watchtower scrubs. What a host sends is stored.

- **`stage.replace` replaces each capture group with `replace`, and nothing
  else.** A regex without a capture group changes nothing, and `$1` in
  `replace` is literal text. So every rule captures exactly the part to hide
  (`password=(\S+)`, not `password=\S+`). The old example had no capture
  groups, so it redacted nothing; SilverBullet's `roles/logship` copied it
  and is fixed in S1.
- Copy the example's scrub block whole, then add the service's own rules
  inside the `// scrub: begin` and `// scrub: end` markers. Secrets are
  caught by key name (anything containing password, secret, token, api key,
  private key, session or credential, with any prefix), in JSON, `key=value`
  and `key: value` forms, quoted or not; Authorization and cookie headers
  whole; connection-string passwords; emails, also `%40`-encoded; IPv4,
  IPv6 and MAC addresses; OS Login names; UUIDs; card numbers unbroken or
  in dashed fours. Not caught: phone numbers, and card numbers typed with
  spaces (a port list looks the same).
- Drop conmon's split lines: every piece of a long line but the last has
  `__journal_container_partial_message="true"` (the example's relabel rule).
  In a Caddy pipeline, also `stage.json` with `drop_malformed = true` on
  `container="caddy"`, so the last piece of a split JSON line can't ship
  either, and strip `[data "…"]` from the WAF rule-match lines you keep.
- IPs are replaced whole. Triage by IP stays on the host (journald,
  fail2ban).
- **Fixture test:** `scripts/check-alloy-scrub.sh <config> <fixture>` runs the
  scrub block in Alloy over tagged lines (`keep:`, `same:`, `drop:`) and
  fails on any line of `<fixture>.forbidden` in the output. Each service's
  fixture holds its own real-shaped lines, made up: a Caddy access line, a
  WAF line, a Coraza audit record over 8 KiB (dropped), an sshd and sudo
  line with an OS Login name, and the service's own.

### Per service

- **Vaultwarden: drop by default.** Ship only:
  - `vaultwarden.service` lines matching known templates (failed logins and
    2FA failures, startup and shutdown), with `IP: …` and the **whole**
    `Username: …` field cut, since a password can be typed into it; drop
    anything with a URL or host name (icon-download warnings name the sites
    of saved logins);
  - backup, restic, dnf, podman-auto-update, `wg-quick@wg-watchtower` and
    alloy;
  - Caddy request, WAF and fail2ban lines only as `stage.metrics` counters,
    then dropped; kernel `nft-drop` lines dropped; user fields cut from
    sshd and sudo.

  Key the allow-list on `unit` from `_SYSTEMD_USER_UNIT` (its quadlets are
  user units of uid 1100) and `__journal_container_name`. Alloy may never
  read `/data`, `coraza-audit.log`, `access.log` or `/var/log/msmtp.log`.
- **SilverBullet:** normalise `/.fs/<page>` URIs: page names are content.
- **Blog:** visitor IPs and `Referer`.
- **Gitea:** user names in auth-failure lines; `?token=`.
- **Gitea CI:** the sink excludes `cloudaudit` (it carries the owner's
  email); scrub `httpRequest.remoteIp`, `userAgent`, and the login in
  webhook "author … is not allowed" lines.
- **Bastion:** OS Login user names (the example's rule).

## Agent peers

The deploy creates each in wg-easy and publishes its config; it may add to
the secrets but never read them. Every run it puts back the agent's
address, keepalive and MTU, the tunnel as its only route both ways, no DNS
and no hooks, and it refuses to publish a config without them. `scripts/bootstrap.sh` (owner-run) creates
the secrets and lets one identity per peer read its own. The list lives in
`infra/internal/names` (`AgentPeers`); tests keep the inventory and
`bootstrap.sh` in step with it.

| wg-easy client | Address | Secret (watchtower-observe) | Read by | Where |
|---|---|---|---|---|
| `bastion` | 10.8.0.129 | `wireguard-bastion-peer` | `watchtower-bastion@watchtower-observe` (W3) | on the VM, at boot |
| `gitea-vm` | 10.8.0.130 | `wireguard-gitea-vm-peer` | `gitea-vm@gitea-496920` | on the VM |
| `vaultwarden-production` | 10.8.0.131 | `wireguard-vaultwarden-production-peer` | `vaultwarden-deployer@vaultwarden-497422` | the deploy job, `no_log` |
| `vaultwarden-disposable` | 10.8.0.132 | `wireguard-vaultwarden-disposable-peer` | `vaultwarden-deployer@vaultwarden-497422` | the deploy job, `no_log` |
| `silverbullet-vm` | 10.8.0.133 | `wireguard-silverbullet-vm-peer` | `cb-infra@silver-bullet-dev` | the deploy job, `no_log` |
| `blog-vm` | 10.8.0.134 | `wireguard-blog-vm-peer` | `blog-vm@dev-blog-494815` | on the VM |

(Each reader is `…@<project>.iam.gserviceaccount.com`.) The service
projects hold no new secret. Rekeying: delete the client in wg-easy; the
next watchtower deploy republishes it, and each service picks it up on its
next deploy or boot (Vaultwarden on a dispatch).

## The changes

One pull request per repo. Each runs the repo's own checks, adds the scrub
fixture test to its CI, and never merges itself, runs an owner script,
reads a secret's value or SSHes anywhere.

### S1: silverbullet-deployment

- `ansible/inventory/group_vars/all/secrets.yml`: `wireguard_peer` from
  `projects/watchtower-observe/secrets/wireguard-silverbullet-vm-peer`;
  `roles/secrets` reads project-qualified ids and never creates one in a
  foreign project.
- `group_vars/all/tunnel.yml`: tenant stays `jasonmross`; add the Mimir URL;
  the `app` label becomes `service`.
- `roles/tunnel`: add the `MTU = 1380` normalisation (it already drops DNS,
  forces the keepalive and checks the config).
- `roles/logship/templates/config.alloy.j2`: the example's scrub block
  (today's rules have no capture groups, so they redact nothing); unix
  (with `/host` paths), self, Caddy `127.0.0.1:2020`, blackbox of
  `127.0.0.1:3000/.instance` and the public `/.instance`; remote_write;
  `/.fs/` normalisation; the Caddy pipeline's JSON check.
- `roles/logship/templates/alloy.container.j2`: read-only `/proc`, `/sys`
  and `/` (rslave) mounts; `GOMEMLIMIT`.
- `roles/edge/templates/{Caddyfile.j2,caddy.container.j2}`: the `:2020` site
  in both network modes; the Coraza audit log to a file; fix the stale
  "Cloud Logging" comment.
- `playbooks/render.yml` for any new template; `README.md` (drop the manual
  `versions add` step).
- Merging runs `site.yml`, which restarts Caddy.

### B1: dev_blog

- Pulumi: `blog:watchtowerPeerSecret` (`infra/pkg/config`,
  `Pulumi.prod.yaml`) becomes instance metadata `watchtower-peer-secret`,
  left out when unset (`infra/pkg/compute`); metadata updates in place.
- `vm/bootstrap.sh`: `wireguard-tools`; `setup_journald` (persistent
  journal, `SystemMaxUse`); a tunnel step in `render_all` that fetches as
  `blog-vm@` with `--project watchtower-observe`, checks and normalises,
  and never echoes; Alloy and the tunnel with a changed flag of their own,
  kept out of the loop that restarts the blog and Caddy; the
  `systemd-journal` gid; `127.0.0.1:2020` in `CADDY_PUBLISH_PORTS` in bridge
  mode.
- New `vm/quadlets/alloy.container` (192 MiB,
  `ConditionPathExists=/etc/wireguard/wg-watchtower.conf`),
  `vm/quadlets/alloy-data.volume`, `vm/config/config.alloy.tmpl`.
- `vm/config/Caddyfile.tmpl`: the `:2020` site; the Coraza audit log to a
  file; fix the "journald → Cloud Logging" comments.
- If the owner's memory check is short (MemAvailable under about 300 MB),
  also `blog:machineType` e2-small (in place, one reboot).
- Merging runs `pulumi up`, then the sync.

### V1: vaultwarden-deployment

- `ansible/playbook.yml`: role `tunnel` after `nftables`, role `logship`
  after `quadlets`, both on `observability_enabled`; each removes its files
  and units when that is false.
- `roles/tunnel` (new): reads `--project watchtower-observe --secret
  wireguard-vaultwarden-<stack>-peer` in the deploy job (`no_log`), checks,
  normalises, `wg-quick@wg-watchtower`, an `OnFailure=` mail drop-in.
- `roles/nftables/templates/main.nft.j2`: `iifname "wg-watchtower" counter
  drop` after the established and loopback rules: nothing comes in over the
  tunnel.
- `roles/logship` (new): the release zip pinned by sha256 (x86_64, no
  third-party repo); user `alloy` in `systemd-journal` only; a unit with
  `MemoryMax=256M`, `GOMEMLIMIT`, `StateDirectory=alloy`,
  `ProtectSystem=strict`, `NoNewPrivileges=yes`,
  `InaccessiblePaths=/data /var/lib/vaultwarden`, `OnFailure=` mail; the
  allow-list config, unix plus systemd, Caddy `:2020`, blackbox `/alive`.
- `caddy/Caddyfile`, `quadlets/caddy.container.j2`: the `:2020` site,
  `PublishPort=127.0.0.1:2020:2020`.
- `group_vars/all.yml`, `inventory/{production,disposable}.yml`: endpoints,
  version and checksum, tenant, `env`, `observability_enabled: true`.
- CI: `alloy fmt` and `validate`, and the fixture test with made-up
  Vaultwarden (including a typed-in password and an icon-download warning),
  Caddy, fail2ban and sshd lines.
- `runbook/README.md`: the intro's "no WireGuard"; the PII check on
  disposable.
- The disposable stack has its own peer and stays out of the alert list.

### G1: gitea, `cicd/` and `infra/`

- `cicd/pkg/identity`: `roles/logging.configWriter` and `roles/pubsub.admin`
  for `cb-infra@gitea-ci-781388` on gitea-496920.
- `pkg/telemetry` in both stacks, gated on a `watchtowerReader` config value:
  topic `watchtower-logs`, pull subscription `watchtower-logs-pull` (ack
  60 s, retention 7 d, no expiry), a sink `watchtower-ci` with a unique
  writer identity and publisher on the topic.
  - gitea-ci-781388: `cloud_run_revision` for `gitea-webhook` and
    `build-status`, logs `run.googleapis.com/stderr` and `requests`.
  - gitea-496920: `k8s_container` in cluster `gitea-runners`, namespace
    `gitea-runner` **only**; `k8s_pod` events from the job namespaces;
    `cluster-autoscaler-visibility`; `nat_gateway`. Never `cloudaudit`, the
    serial console, `kube-system`, `gmp-system` or `gitea-ops`.
- For `watchtower-gcp-reader@watchtower-observe.iam.gserviceaccount.com`:
  `pubsub.subscriber` on each subscription, and a **custom role** with only
  `monitoring.timeSeries.list`, `monitoring.metricDescriptors.list` and
  `monitoring.monitoredResourceDescriptors.list` (not `monitoring.viewer`,
  which reads notification channels and the owner's email).
- `infra/pkg/project/apis.go`: `pubsub.googleapis.com`. Docs: `runners.md`,
  `cicd.md`.

### W2: here, GCP pull (after G1 and the reader key)

- `build/alloy/`: our own Alpine image from the release binary (arm64,
  tagged, Trivy-gated), in the images matrices.
- `ansible/roles/gcppull`: `loki.source.gcplog` pulling both subscriptions
  on all three nodes; `__gcp_*` relabelled to `project`, `resource_type`,
  `namespace`, `container`, `cloud_run_service` (pod in structured
  metadata); the runner's own level via `stage.logfmt`; Cloud Run's slog
  via `stage.json`; the scrub; writes to `loki.internal` and
  `mimir.internal` with `X-Scope-OrgID: jasonmross`.
  `prometheus.exporter.gcp` on `watchtower-3` only, scraped every 5 m, with
  `extra_filters` for cluster `gitea-runners` and the runner namespaces. A
  384 MiB cap. The role skips itself without the key.
- Secret `gcp-telemetry-reader-key` (setup action `?@`, a podman secret);
  `scripts/rotate-gcp-key.sh reader`.

### W3: here, the bastion

- `scripts/bootstrap.sh` step 7: service account `watchtower-bastion@`,
  reader of `wireguard-bastion-peer` only, and an in-place update (stop, set
  the account, metadata, start; the disk and host key stay).
- The startup script: `wireguard-tools` and the Alloy `.deb` (checked
  against `SHA256SUMS`, apt with a lock timeout), a 192 MiB drop-in, the
  peer fetched with the metadata token, checked and normalised. The peer
  never goes in instance metadata.
- nftables `meta skuid != 0` drop to 169.254.169.254, so OS Login users (the
  deployer among them) can't read the peer with the VM's token. Tested
  before it ships.
- `config/alloy/bastion.alloy`, validated and fixture-tested in CI.

### G2: gitea, the VM (after the Ansible cutover)

- Pulumi: `gitea:watchtowerPeerSecret` as metadata, left out when unset, so
  the rehearsal VM never joins with production's key.
- `vm/ansible/roles/tunnel` (an on-VM fetch as `gitea-vm@`, in the
  `gitea-render-secrets` style) and `roles/logship` (the quadlet and its
  own handler, never under `vm/systemd/`), after `firewall` in `site.yml`.
- `app.ini` `[metrics] ENABLED = true`; Caddy `handle /metrics { respond 404 }`
  publicly, the `:2020` site, the audit log to a file.
- Golden fixtures get a **dummy** peer: the repo mirrors to GitHub.

### W4: here, alerts (after every source is verified)

Grafana-provisioned rules per host in a `watchtower_telemetry_sources` list
(verified hosts only): silence (`absent_over_time` on node metrics and
logs), shipping errors, memory, swap, disk, failed units, probes,
certificate expiry, Caddy 5xx; for Gitea CI, `absent_over_time` on its logs
and one Cloud Monitoring series, the subscription backlog, NAT drops and
Cloud Run 5xx. One notification group to the Healthchecks.io check
`watchtower-telemetry-alerts` (secret `healthchecks-telemetry-alert-url`),
so it means "anything firing". A fleet dashboard.

## Rollout

In order, each after the one before is verified:

1. **W1** (this repo: the tenant, the agent peers, the gating). The owner
   runs `scripts/bootstrap.sh` from its branch first, then it merges and its
   deploy creates the six peers.
2. **S1**, then the gating test from silverbullet-vm (docs/runbook.md,
   "WireGuard peers"), then **B1**.
3. **V1**: a disposable cycle from its branch, then production.
4. **G1** (the owner runs `make ci-up` from its branch), then **W2** (the
   owner runs `bootstrap.sh` and `rotate-gcp-key.sh reader`).
5. **W3** (the owner runs `bootstrap.sh` from its branch).
6. **G2**, after the Gitea cutover.
7. **W4**.

Merges and deploys: Monday to Friday, 14:00 to 21:00 UTC, about two hours
apart. Never on Sunday or 00:00 to 09:30 UTC (watchtower's 05:00 deploy,
the 02:30 to 03:30 backups, the reboot windows).

## Verification

In Grafana Explore, `Loki (jasonmross)` and `Mimir (jasonmross)`, for each
host `H`:

- `count by (job) (up{host="H"})`: one per job, all 1.
- `sum by (unit, container) (count_over_time({host="H"}[15m]))`: logs flow.
- `rate(prometheus_remote_storage_samples_failed_total{host="H"}[10m])` is
  0; `loki_write_dropped_entries_total{host="H"}` is flat.
- `node_memory_MemAvailable_bytes{host="H"} / node_memory_MemTotal_bytes{host="H"}`
  stays above 0.15 for 48 h (the blog above all).

**PII, over 24 h of real traffic; any hit blocks the next merge:**

```
{host="H"} |~ "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
{host="H"} |~ "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[a-z]{2,}"
{host="H"} |= "eyJ"
{host="H"} |= "\"transaction\""
{host="H"} |~ "(?i)\"(cookie|authorization)\""
{host="H"} |~ "_(gmail|googlemail)_com"
{service="silverbullet"} |~ "/\\.fs/[^<]"
```

Vaultwarden, on disposable first: fail a login with a made-up email, and
type a made-up "password" into the username field; neither appears, nor
`Username:` or `IP: `; only allow-listed units appear; the failed-login
counter rises.

Gitea CI: a pull request somewhere shows in `{service="gitea-ci",
namespace="gitea-runner"}` within about a minute; the subscription backlog
stays near 0; `{service="gitea-ci"} |= "cloudaudit"` is empty.

Traces: a Tempo search finds nothing, so nothing exports OTLP by mistake.
