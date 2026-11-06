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
| Agent | Grafana Alloy **v1.21.3**, pinned: an image by digest (`docker.io/grafana/alloy:v1.21.3@sha256:…`), a release zip or `.deb` by sha256 from the release's `SHA256SUMS`. No `AutoUpdate=` |
| Form | A **rootful podman quadlet** with `Network=host` on SilverBullet, the blog and the Gitea VM; a **host binary with a systemd unit** on Vaultwarden (its quadlets are rootless) and the bastion (`.deb`) |
| Memory | 2 GB hosts: 256 MiB cap (`MemoryMax=` or `PodmanArgs=--memory`), `GOMEMLIMIT=200MiB`. 1 GB hosts (blog, bastion): 192 MiB, `GOMEMLIMIT=150MiB`. An OOM then kills Alloy, not the app |
| Listeners | Alloy's UI on `127.0.0.1:12345` only. No OTLP receiver in v1 |
| State | Alloy's storage path on persistent disk (a named volume, or `StateDirectory=alloy`): the journal position and the remote-write WAL survive restarts |
| WireGuard | Interface `wg-watchtower`, unit `wg-quick@wg-watchtower`, config `/etc/wireguard/wg-watchtower.conf`, root 0600 |
| Peer config | From Secret Manager `projects/watchtower-observe/secrets/wireguard-<peer>-peer/versions/latest`, read cross-project by the one identity granted it (below). **Never printed**: no `set -x`, `no_log: true`, and nothing on boot output (the blog's and Gitea's reach Cloud Logging) |
| Peer checks | watchtower's deploy resets each agent's hooks, DNS and routes on every run and refuses to publish a config that has any; check again on the host, since the config runs there as root. Judge each line as wg reads it: cut any `#` comment, remove all whitespace, and take keys in any case, since wg and wg-quick accept `Allowed IPs` and `Fw Mark`. Refuse anything but printable ASCII, tabs and newlines. Allow-list the keys (`PrivateKey`, `Address`, `MTU`, `DNS`, `PublicKey`, `PresharedKey`, `AllowedIPs`, `PersistentKeepalive`, `Endpoint`) and refuse any other, so every hook, `Table`, `FwMark` and `SaveConfig` goes. Refuse the config unless it has exactly one `[Interface]` and one `[Peer]`, with an `Endpoint` and one `AllowedIPs`, exactly `10.8.0.0/24`. Then write the config afresh from the checked values, never the fetched text: no `DNS`, `PersistentKeepalive = 25`, `MTU = 1380` (watchtower sets both). A full tunnel would send the metadata server's traffic to the proxy and break the VM's credentials, image pulls and DNS-01 |
| No peer | Only a missing or empty secret takes telemetry down: a warning, never a failed deploy, then stop and disable the tunnel and Alloy and remove their config. Any other fetch error (network, 5xx, token, `PERMISSION_DENIED`) warns and leaves the tunnel and Alloy running as they are. To revoke a peer, delete its client in wg-easy |
| Labels | Everything: `service`, `host`, `env` (`production`, or `disposable`). Logs also `unit`, `container`, `level`. **Never** a label from an IP, user, email, URL path, UUID or pod name. The scrub block rewrites `unit` from `user@<uid>.service` to `user@.service`, `user-runtime-dir@<uid>.service` to `user-runtime-dir@.service`, and Podman's health check units (`<64 hex digits>-<hex digits>.service`) to `podman-healthcheck.service` |
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
  caught by key name (anything containing password, passphrase, passcode,
  secret, token, bearer, api key, private, preshared, access, signing,
  encryption, ssh, auth or otp key, otp or auth code, session, credential or
  csrf, with any prefix), with a word after it (`Session ID:`) or brackets on
  it (`user[password]=`), in JSON, XML, `key=value` and `key: value` forms,
  with `=>`, `:=` or `==` too, quoted or not, or percent-encoded in a URL; a
  flag and its value (`--password x`), and a name and value side by side as
  strings (an argument array, a Python header tuple); a JSON value whole, as a
  string with escaped quotes, a number, an array or an object, and the same in
  a JSON string quoted inside a line; a wrapper or an opening bracket
  (`Some("x")`, `[ "x" ]`) to the end of the line; a value in `\"` whole; any
  other bare value up to the next blank, `&` or closing quote; `pass`, `otp`
  and `auth` as a whole key or its last part, in camelCase or with a number
  too, in JSON or with `=`; `sid`, `ssn`, `cvv` and `cvc` the same way, `ssn`,
  `cvv` and `cvc` with `:` too; Authorization and cookie headers whole, under
  any name that holds one; Basic credentials; other credentials in a query
  string, nested and encoded too; connection-string passwords, Go's MySQL form
  too; emails, in any alphabet, in quotes, `%40` or `%2540`-encoded or
  `\u`-escaped; IPv4, IPv6 and MAC addresses, next to a letter or `_`, an IPv4
  dashed in a hostname and an IPv6 percent-encoded; OS Login names; OS Login
  uids of 10 digits or more after `uid=` (`auid=` and `euid=` too) or `UID `,
  or in `user-<uid>.slice`, `user@<uid>.service`,
  `user-runtime-dir@<uid>.service` and `/run/user/<uid>`; those two units in the
  `unit` label, whatever the uid; sudo's command and environment, on any unit
  (`ENV=` after sudo's ` ; ` and `COMMAND=` to the end of the line, and
  `(command continued)`, so who ran it and as whom stay); tokens by their shape
  (`ghp_`, `ya29.`, `AKIA`); SSH public keys (`ssh-ed25519`, `ssh-rsa`,
  `ecdsa-sha2-*`, the key itself); JWTs of two, three or five parts; UUIDs; SSH
  key fingerprints (`SHA256:`, `SHA-256:`, `SHA1:`, `MD5:`); the lines wg's
  errors quote; card numbers of 15 or 16 digits, unbroken or in dashed fours.
  Not caught: phone numbers; card numbers typed with spaces (a port list looks
  the same), of another length or in dashed Amex groups; `pass:`, `otp:` or
  `auth:` outside JSON (`auth: ok` looks the same); outside sudo's `COMMAND=`, a
  short flag joined to its value (`-pX`) and curl's user and password flag with
  a separate value; a secret in prose (`password is x`); a Basic value of letters
  only (`basic authentication` looks the same); a bare value with a quote inside
  it; a uid under 10 digits in a line, or in any other context (`UID:`, `UID=`,
  `_UID=`); an SSH key's comment (`pat@laptop`); an SSH certificate
  (`ssh-ed25519-cert-v01@openssh.com AAAA…`); a fingerprint after a blank
  (`SHA-256: AB:CD`) or under another name (`SHA-1:`, `SHA512:`). systemd's
  `session-N.scope:` and instantiated units (`wg-quick@wg0.service`), sudo's
  `TTY=… ; PWD=/… ;`, sshd's `Starting session:`, a program's `name[pid]:`, an
  app's own `ENV=production`, a key type named alone (`key type ssh-rsa`), a bare
  hash or git sha, a `sha256:` digest, and a hash in lower-case hex after `SHA1:`
  (40 digits) or `SHA-256:` (64) are left alone; so are root and small uids.
  Some ordinary lines lose a word, and that is the safe way round: `byPass=1`,
  `isAuth=true`, `?state=open`, an all-hex `dead::beef`, `/etc/passwd: No such
  file`, an app's own `COMMAND=x`, and a `SHA256:` before a hash.
- Drop conmon's split lines: every piece of a long line but the last has
  `__journal_container_partial_message="true"` (the example's relabel rule).
  The block's first stage drops any line on `container="caddy"` that isn't
  JSON, so the last piece of a split line can't ship either. It also strips
  `[data "…"]` and `[msg_match_N …] [data_match_N …]` from WAF lines, and
  drops a line where matched data survives.
- IPs are replaced whole. Triage by IP stays on the host (journald,
  fail2ban).
- **Fixture test:** `scripts/check-alloy-scrub.sh <config> <fixture>` runs the
  scrub block in Alloy over tagged lines (`keep:`, `same:`, `drop:`) and
  fails on any line of `<fixture>.forbidden` in the output. If there is a
  `<fixture>.caddy.log`, it runs too, under `container="caddy"`, with each
  line's tag inside it (`keep:c<n>`, `drop:c<n>`), so the JSON check is really
  exercised. `<fixture>.expect`, if there is one, holds whole lines exactly as
  they must come out, for what stays readable on a line that changes.
  `<fixture>.units`, if there is one, holds `<unit in> <unit out>` pairs, each
  run under that `unit` label, and fails on any other label coming out; the
  harness reads the block alone, so this tests the block's rewrite, not the
  relabel rule that sets the label. Each service's fixture holds its own real-shaped lines, made
  up: a Caddy access line, a WAF line, a Coraza audit record over 8 KiB
  (dropped), an sshd and sudo line with an OS Login name, and the service's
  own.

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
- **Bastion:** OS Login user names (the example's rule); certificate key IDs
  and OS Login uids, also out of the `unit` label (`user@.service`,
  `session.scope`); sudo's `COMMAND=` to the end of the line ("someone ran
  sudo" still ships), and whatever follows `invalid user`.

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
  `monitoring.timeSeries.list` and `monitoring.metricDescriptors.list`, the
  only two calls `prometheus.exporter.gcp` makes (not `monitoring.viewer`,
  which reads notification channels and the owner's email).
- `infra/pkg/project/apis.go`: `pubsub.googleapis.com`. Docs: `runners.md`,
  `cicd.md`.

### W2: here, GCP pull (after G1 and the reader key)

- `build/alloy/`: our own Alpine image from the release binary (arm64,
  tagged, Trivy-gated), in the images matrices. The binary is linked against
  glibc, so the image carries `gcompat`. v1.21.3 here, the newest stable; the
  contract above still says what the services pin.
- `ansible/roles/gcppull`: `loki.source.gcplog` pulling both subscriptions
  (`watchtower-logs-pull` in `gitea-496920` and in `gitea-ci-781388`, one a
  project) on all three nodes; `__gcp_*` relabelled to `project`, `resource_type`,
  `namespace`, `container`, `cloud_run_service` (pod in structured
  metadata); the runner's own level via `stage.logfmt`; Cloud Run's slog
  via `stage.json`; the scrub; writes to `loki.internal` and
  `mimir.internal` with `X-Scope-OrgID: jasonmross`.
  `prometheus.exporter.gcp` on `watchtower-3` only (`gcppull_metrics_host`),
  scraped every 5 m, with `extra_filters` for cluster `gitea-runners` and the
  runner namespaces. A 384 MiB cap. The role skips itself without the key: no
  file, no image pull, no failure.
- Secret `gcp-telemetry-reader-key` (setup action `?@`, a podman secret);
  `scripts/rotate-gcp-key.sh reader`.

As built:

- **Labels:** `service="gitea-ci"`, `host="gcp"` and `env="production"` on all of
  it but Alloy's own metrics. `host` is the one value, not the pulling node, which
  would split every stream three ways. Every other label has a known value: anything
  else is dropped (below).
- **The shared block is as in the example, byte for byte,** taken from it when the
  config renders, and this pipeline's own rules are a `loki.process "gcp"` of their
  own in front of it, since they rebuild each line.
- **Default deny.** A resource and log not in the sinks' filters, or a project,
  cluster, namespace, container or function other than the allowed ones, is dropped.
  This is in `loki.process`: on this source a relabel rule that drops an entry only
  strips its labels, and the entry still ships.
- **What ships of each kind.** `use_full_line` brings in the whole log entry, and a
  line still holding it is dropped. Each kind rebuilds its line:
  - NAT flow: status, gateway, region, VM, protocol, destination port. Never an
    address.
  - Autoscaler: the pool's name, counts and Google's reason codes. Never the rest of
    the payload.
  - Cloud Run request: status and latency, and the method and path only as `POST` and
    `/`, which is all the two functions serve. Anyone who can reach the webhook's
    URL writes those, so anything else is the word `other`.
  - slog record: `msg`, `level`, `event`, `delivery`, `reason`, `error`, `topic`,
    `attributes`, `build`, `context`, `sha`, `state`, `status`, `current`, `code` and
    `message`, the keys `webhook.go` and `status.go` write. A key they add later needs
    adding in `config.alloy.j2`, or it doesn't ship.
- **Free text is the exception.** A runner's line, a pod event's message, the slog
  `reason`, `error` and `attributes`, and a stderr line that isn't JSON (a Go panic)
  have no fields to name. Only this pipeline's replace rules and the shared block
  stand behind them. Among what they can still hold: branch names, image references
  and the repo names a runner logs.
- **Runner lines:** only `time="<date>…" level=<word> msg=`, one line of it, from the
  `runner` container. This stops stray output, not a line in that same format, which
  a runner at `log.level: debug` might write around a job's output, or a job could
  forge if its output reached this log. What keeps job output out is the runner's
  `log.level: info` and the sink's filter.
- **Pod names:** in structured metadata, which nothing scrubs, so only a name with no
  `@` or dot gets there. Any other entry ships without a pod.
- **Logins:** `author …` and `pusher … is not allowed`, as well as `head is in …`
  and `delivery for "…"`, which name a fork's owner or another repo.
- **Clients:** `remoteIp`, `serverIp`, `userAgent` and `referer`, if free text holds
  them under those names, as a JSON key or `key=value`, and a user agent (`user-agent`,
  `user_agent`, `User-Agent`, `userAgent`) as a header too.
- **In an outage:** Alloy acknowledges an entry to Pub/Sub when `loki.write`'s queue
  takes it, not when Loki does (`pull_target.go`, v1.21.3). So everything past the
  queue waits in Pub/Sub, for up to 7 days, but a restart or a crash during the outage
  loses the queue, about 10 MiB a node. With `use_incoming_timestamp`, Loki can also
  refuse an entry more than about an hour behind the newest in its stream, which a
  long catch-up can produce.
- **Its own health:** `prometheus.exporter.self` on every node, `job="alloy"`,
  `service="gitea-ci"`, `env="production"` and `host` the node's own name. Each drop
  rule has its own `reason` on `loki_process_dropped_lines_total`.
- **A failed install warns and the deploy goes on,** since the nodes go one at a time
  and telemetry from CI must not stop a deploy of watchtower. `watchtower-health`
  alerts on a unit that stays down.
- **Metrics:** a pod's name is never a label, so `pod_name` becomes a `pod_slot` of
  1024: dropping it alone would make a namespace's pods one series, whose samples
  Mimir refuses as duplicates. `nat_ip` goes too. Prefixes are named one by one in
  `config.alloy.j2`, enough for W4's backlog, NAT drops and Cloud Run 5xx. Samples
  carry Cloud Monitoring's own times, and the scrape comes every 5 minutes, so an
  instant query or a short `rate()` can be empty: use windows of 15 minutes or more.
- **Fixture tests:** `scripts/check-gcppull-scrub.sh` runs the rendered config over
  `config/alloy/testdata/gcppull.log`, made-up entries in every shape and some that
  must not ship, through the real source in push mode. `<fixture>.expect` holds
  everything that may come out, labels and metadata too.
  `scripts/check-gcppull-metrics.sh` does the same for the metrics half, over
  `gcppull.metrics`.
- **Owner's steps,** in order: gitea's change first (`make ci-up`, merge, its infra
  deploy; the runbook's "Gitea CI's logs and metrics"), then `scripts/bootstrap.sh`
  from this branch, `scripts/rotate-gcp-key.sh reader`, and a deploy.

### W3: here, the bastion

- `scripts/bootstrap.sh` step 7: service account `watchtower-bastion@`,
  reader of `wireguard-bastion-peer` and, as built, its ping URL only, and an in-place update (stop, set
  the account, metadata, start; the disk and host key stay).
- The startup script: `wireguard-tools` and the Alloy `.deb` (checked
  against `SHA256SUMS`, apt with a lock timeout), a 192 MiB drop-in, the
  peer fetched with the metadata token, checked and normalised. The peer
  never goes in instance metadata.
- nftables `meta skuid != 0` drop to 169.254.169.254, so OS Login users (the
  deployer among them) can't read the peer with the VM's token. Tested
  before it ships.
- `config/alloy/bastion.alloy`, validated and fixture-tested in CI.

As built: the account is made with the others (step 4) and granted through
`agent_readers`. Step 7 gives `watchtower-deployer`
`roles/iam.serviceAccountUser` on it, because OS Login admits a user to a VM
that runs as a service account only then (the owner's decision, 2026-11-01).
It attaches the account only after the guard's ruleset is confirmed, by a guest
attribute only root can write once the guard is on, and asks again of the boot
with the account: two restarts the first time.

A new ruleset goes on under a 10-minute rollback (the owner's decision,
2026-11-01; `config/bastion/ruleset.sh`, and the runbook's "A new ruleset"). A
login cancels it, and bootstrap dispatches `bastion-confirm.yml` to log in as
the deployer. sshd runs only with the guard in the kernel, or on a VM with no
account. An account goes on only over a confirmed ruleset, and a ruleset that
won't load at a boot brings the floor, a small copy of the guard built into the
tool, before the network comes up. Nothing of a user's runs without a login: no
crontab, at job or lingering. So nothing of a user's runs with a token and no
guard. The one case left is nft itself loading nothing, not even the floor, and
then sshd stays down.

The startup script, the ruleset, its tool and the Alloy config are files
(`config/bastion/`, `config/alloy/bastion.alloy`) that bootstrap puts in the
VM's metadata. The guard leaves DNS (53), DHCP (67) and NTP (123) open to every
uid, since Alloy, apt, systemd-networkd and chrony need them and they carry no
credential, and refuses the rest at once (reject, not drop), so a lookup that
hits it fails fast instead of hanging. A drop-in clears `nftables.service`'s
`ExecStop`, so a package upgrade's restart reloads rather than flushes.
`scripts/check-bastion.sh` tests the guard, the rollback and the peer checks in
Debian 13 (CI's `configs` job), and says what only the VM can show. Only a
missing or empty secret takes the tunnel and Alloy down; any other failure to
read it warns and leaves them running, and so does a config that fails the
checks. The peer checks go past the contract's: the host reads a line as `wg`
does and admits only the settings an agent needs, in their shape, so a config
with a stray character in a key is refused here rather than echoed by `wg` into
the journal.

The owner added two things to this (2026-11-01). The bastion pings a
Healthchecks.io check of its own, `watchtower-bastion`, after each boot and every
day, once the guard is loaded and sshd is active, with a URL kept in
`healthchecks-bastion-url` that only it may read. And new metadata is the way in
when SSH is gone, with `config/bastion/recovery.sh` ready to put there; the serial
console only reads, and there is no local password user (the runbook's "The
bastion with SSH gone").

The owner settled five more on 2026-11-04 (the runbook has the detail):

- **Recovery stays gated.** `recovery.sh` never starts sshd itself, only the tool
  does, through its gate, and with no usable tool it doesn't ask for sshd at all.
- **A last good copy of the ruleset's tool.** A new `watchtower-ruleset` goes in
  only once it passes a self-check in a network namespace of its own: no rules
  must not pass for a guard, and its gate must keep sshd down with no guard; its
  floor must pass `nft --check`, load and guard; and its gate must let sshd run with
  the floor on. The last tool that passed and brought sshd up is kept, and a tool
  that fails at a boot gives way to it.
- **No unprivileged user namespaces:** `kernel.unprivileged_userns_clone = 0`,
  Debian's own knob, which leaves root's and systemd's (`PrivateUsers=`) alone.
- **A per-run login nonce:** bootstrap's login check counts only a login whose file
  is named by its run's nonce, so a rerun can't be satisfied by an earlier run's
  login, session or attribute.
- **A run nonce against forged attributes:** each start bootstrap makes gets a fresh
  nonce in metadata while the VM is stopped, every attribute carries its boot's, and
  only values with it count. A value written on the unguarded boot with no account,
  where any user may write one, can't carry the nonce of the boot with the account.

A review of those, answered the same day, tightened them: a tool becomes the last good
copy only at a boot with sshd active, the guard on (or no account) and no trial
pending; `recovery.sh` stops an sshd the boot left up with no guard on a VM that may
have an account; every start bootstrap makes, its exit trap's included, gets a fresh
run nonce; a tool's `apply` at a boot has 5 minutes and its self-check 2; and bootstrap
warns when unprivileged user namespaces are on.

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
5. **W3** (the owner runs `healthchecks.sh`, then `bootstrap.sh`, from its branch,
   then tries the recovery once, as the runbook's "The bastion with SSH gone"
   says).
6. **G2**, after the Gitea cutover.
7. **W4**.

Merges and deploys: one service at a time, at any time of day, but never
while that repo's deploy is already running.

## Verification

In Grafana Explore, `Loki (jasonmross)` and `Mimir (jasonmross)`, for each
host `H`:

- `count by (job) (up{host="H"})`: one per job, all 1.
- `sum by (unit, container) (count_over_time({host="H"}[15m]))`: logs flow.
- `rate(prometheus_remote_storage_samples_failed_total{host="H"}[10m])` is
  0; `loki_write_dropped_entries_total{instance="H"}` is flat. The
  `loki_write_*` series select on `instance`, not `host`: Loki's client sets
  its own `host` label on them (Loki's address,
  `watchtower.jasonmross.dev:3100`), and a series' own label beats
  `external_labels`, so `{host="H"}` matches nothing and looks flat. Alerts on
  them must use `instance` too.
- `node_memory_MemAvailable_bytes{host="H"} / node_memory_MemTotal_bytes{host="H"}`
  stays above 0.15 for 48 h (the blog above all).

**PII, over the first hour of real traffic; any hit blocks the next merge:**

```
{host="H"} |~ "(?:^|[^0-9])(?:\\d{1,3}\\.){3}\\d{1,3}(?:$|[^0-9])"
{host="H"} |~ `[\p{L}\p{N}._%+'!#$*^~-]+(?:@|%40|%2540|\\u0040)[\p{L}\p{N}.-]+\.[A-Za-z]{2,}` !~ `@[\w.:\\-]+\.(?:service|socket|timer|target|mount|path|slice|scope)\.?(?:$|[^\w.-])`
{host="H"} |~ "eyJ[A-Za-z0-9_-]{5,}"
{host="H"} |= "\"transaction\""
{host="H"} |~ `(?i)\\*"[\w-]*(cookie|authorization)[\w-]*\\*"\s*:\s*\[?\s*\\*"`
{host="H"} |~ "_(gmail|googlemail)_com"
{host="H"} |~ "\\b(SHA256|SHA-256|SHA1|MD5):[A-Za-z0-9+/]"
{host="H"} |~ `uid=\d{10}|\bUID \d{10}|\buser-\d{10,}\.slice|\buser(-runtime-dir)?@\d{10}|/run/user/\d{10}`
{host="H", unit=~"(user|user-runtime-dir)@[0-9]+\\.service"}
{host="H"} |~ `\bCOMMAND=[^\[]|;\s*ENV=[^\[]|\(command continued\)[^\[]`
{host="H"} |~ `ghp_[A-Za-z0-9]{16}|ya29\.[A-Za-z0-9._-]{16}|AKIA[0-9A-Z]{16}`
{host="H"} |~ `(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9-]+)\s+AAAA`
{service="silverbullet"} |~ `/\.fs/[^<"\\]`
{service="silverbullet"} |~ `"uri":"/([^.<"]|\.(fs|revisions|proxy)/[^<"])|\[uri \\"/([^.<\\]|\.(fs|revisions|proxy)/[^<\\])|[?&]from=[^<]|Proxying to [^<]`
{service="gitea-ci"} |~ "(?:^|[^0-9])(?:\\d{1,3}\\.){3}\\d{1,3}(?:$|[^0-9])"
{service="gitea-ci"} |~ `[\p{L}\p{N}._%+'!#$*^~-]+(?:@|%40|%2540|\\u0040)[\p{L}\p{N}.-]+\.[A-Za-z]{2,}`
{service="gitea-ci"} |~ `(?i)(remote_?ip|server_?ip|user[-_ ]?agent|referr?er)\\*"?\s*[:=]\s*\\*"?[^\[\s\\"]`
{service="gitea-ci"} |~ `\b(author|pusher) [^\[]+ is not allowed|\bhead is in [^\[]|\bdelivery for \\*"[^\[]`
{service="gitea-ci"} |~ `"(logName|insertId|httpRequest|protoPayload)"\s*:`
{service="gitea-ci"} |= "cloudaudit"
{service="gitea-ci"} |~ "eyJ[A-Za-z0-9_-]{5,}"
{service="gitea-ci", resource_type="k8s_container", namespace!="gitea-runner"}
{service="gitea-ci", resource_type="k8s_container", container!="runner"}
{service="gitea-ci", resource_type="k8s_container"} !~ `^time="\d{4}-[^"]+" level=\w+ msg=`
{service="gitea-ci", resource_type="k8s_pod", namespace!~"gitea-jobs|gitea-jobs-arm64"}
{service="gitea-ci", project!~"gitea-496920|gitea-ci-781388"}
{service="gitea-ci", pod=~".+"}
```

The last query looks in stream labels only, and `pod` belongs in structured
metadata, so it stays empty. In Mimir, `count(count_over_time({service="gitea-ci",
pod_name!=""}[15m]))` and the same with `nat_ip!=""` are empty too.

The email query skips a line that names an instantiated systemd unit
(`wg-quick@wg-watchtower.service`), so an address on the same line as one goes
unseen.

The JWT queries want at least five characters after `eyJ`: a bare `eyJ` at
the end of a random WAF transaction id matched on blog-vm on 2026-11-03. Any
real token still matches, with or without its dots.

The fingerprint query also hits a hash in lower-case hex after `SHA1:` or
`SHA-256:`, which the scrub leaves alone; a hit in that shape is no leak.

The cookie and authorization query looks for a value that survived: the scrub
keeps the key and replaces all of its value, so the key alone is no hit. The
`/.fs/` queries skip the listing route (`/.fs/` and nothing after it), which
names no page.

Vaultwarden, on disposable first: fail a login with a made-up email, and
type a made-up "password" into the username field; neither appears, nor
`Username:` or `IP: `; only allow-listed units appear; the failed-login
counter rises.

Gitea CI: a pull request somewhere shows in `{service="gitea-ci",
namespace="gitea-runner"}` within about a minute; the subscription backlog
stays near 0; `{service="gitea-ci"} |= "cloudaudit"` is empty. It has no host of
its own to check: `{service="gitea-ci"}` by `project` shows both projects' logs,
`max_over_time(stackdriver_pubsub_subscription_pubsub_googleapis_com_subscription_num_undelivered_messages{service="gitea-ci"}[15m])`
one series a project, and `journalctl -u gcppull` on any node why not. Cloud
Monitoring's series come every 5 minutes with its own timestamps, so query them over
15 minutes or more: an instant query or a short `rate()` can be empty. Alloy's own
metrics are ordinary, under `job="alloy"` and each node's name:
`sum by (reason) (rate(loki_process_dropped_lines_total{service="gitea-ci"}[15m]))`
says what is being dropped and why, and
`rate(loki_write_dropped_entries_total{service="gitea-ci"}[15m])` stays 0.

Traces: a Tempo search finds nothing, so nothing exports OTLP by mistake.
