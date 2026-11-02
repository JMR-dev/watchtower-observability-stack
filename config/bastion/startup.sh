#!/bin/bash
# The break-glass bastion's startup script. GCE runs it as root at every
# boot; scripts/bootstrap.sh (step 7) puts it in the VM's metadata with the
# three files it reads from there, watchtower-nftables (nftables.conf here),
# watchtower-ruleset (ruleset.sh here) and watchtower-alloy
# (config/alloy/bastion.alloy). Idempotent, and it never prints the peer config
# or the VM's token: its output goes to the serial console and the journal,
# which Alloy ships.
#
#   1. The metadata guard (nftables.conf): only root reaches the metadata
#      server, so only root can use the VM's token. First, since sshd waits
#      on it. A new ruleset goes on under a 10-minute rollback that a login
#      cancels, and sshd runs only with the guard loaded or on a VM with no
#      token (ruleset.sh). Nothing else runs if sshd may not.
#   2. Security updates every day, rebooting at 04:00 UTC when one needs it.
#   3. Says so in a guest attribute once apt is done: scripts/bootstrap.sh stops
#      the VM for its account only after that.
#   4. Its agent peer (docs/client-telemetry.md), read from Secret Manager
#      with that token, checked and normalised, as wg-quick@wg-watchtower. A
#      missing or empty secret, and nothing else, takes the tunnel and Alloy
#      down: stopped and disabled, and their config removed. Any other failure
#      to read it, or a config that fails the checks, warns and leaves them
#      running as they are. Revoking a peer is done by deleting its client in
#      wg-easy.
#   5. Grafana Alloy from the release's .deb, pinned by sha256, run with the
#      config from metadata, capped at 192 MiB, and only with the tunnel.
#   6. Warns, never fails, when Alloy isn't ready or the tunnel has no
#      handshake within 2 minutes.
#
# scripts/check-bastion.sh tests the peer checks, the guard and the rollback.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

MDS="http://169.254.169.254/computeMetadata/v1"
SECRETS_API="https://secretmanager.googleapis.com/v1"
# The bastion's agent peer, the one secret its service account may read. A
# Go test keeps it equal to names.AgentPeers.
PEER_SECRET="projects/watchtower-observe/secrets/wireguard-bastion-peer"
TUNNEL_CIDR="10.8.0.0/24"
WG_CONF="/etc/wireguard/wg-watchtower.conf"
ALLOY_VERSION="1.21.2"
# alloy-1.21.2-1.amd64.deb, from the release's SHA256SUMS.
ALLOY_DEB_SHA256="80750b6740147ee6d9d860988989dd28bdb048ab0b27b7c02da7876ea5015dad"
ALLOY_CONFIG="/etc/alloy/bastion.alloy"
ALLOY_DROPIN="/etc/systemd/system/alloy.service.d/watchtower.conf"
RULESET_TOOL="/usr/local/sbin/watchtower-ruleset"
# ruleset.sh's exit status when it rolled back and is rebooting.
RULESET_REBOOTING=75

log() { printf 'bastion: %s\n' "$*"; }
warn() { printf 'bastion: warning: %s\n' "$*" >&2; }
die() { printf 'bastion: error: %s\n' "$*" >&2; exit 1; }

# The daily upgrade may hold dpkg's lock at boot: wait for it. With the usual
# umask, not this script's.
apt_get() { (umask 022 && apt-get -q -o DPkg::Lock::Timeout=600 "$@"); }

# A stop or a crash in the middle of an install leaves dpkg's journal behind,
# and apt then refuses everything until dpkg has replayed it. dpkg has no lock
# timeout of its own, so this waits as long as apt_get would.
dpkg_heal() {
  local i
  for i in $(seq 60); do
    (umask 022 && dpkg --force-confdef --force-confold --configure -a) && return 0
    [[ "$i" -eq 60 ]] || sleep 10
  done
  die "dpkg --configure -a did not finish within 10 minutes"
}

apt_install() {
  dpkg_heal
  apt_get update
  apt_get install -y "$@"
}

# True when every package named is fully installed: dpkg -s also says yes to a
# package an interrupted install left half unpacked.
installed() {
  # shellcheck disable=SC2016 # dpkg-query's format, not the shell's
  [[ "$(dpkg-query -W -f '${db:Status-Status}\n' "$@" 2>/dev/null | grep -cx installed)" == "$#" ]]
}

mds() { curl -fsS --retry 5 --retry-connrefused --max-time 30 -H 'Metadata-Flavor: Google' "${MDS}/$1"; }

# get <url> <out> [curl args...]: the body into out; prints the HTTP status,
# 000 when nothing answered.
get() {
  local url=$1 out=$2 code
  shift 2
  code="$(curl -sS --retry 5 --retry-connrefused --max-time 30 -o "$out" -w '%{http_code}' "$@" "$url")" || true
  [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
  printf '%s\n' "$code"
}

# put <src> <dest> <mode> <group>: installs src as dest, owned by root, when
# they differ; true when it did. Called as a condition, where set -e is off,
# so every failure dies by hand.
put() {
  local src=$1 dest=$2 mode=$3 group=$4
  if [[ -f "$dest" ]] && cmp -s "$src" "$dest"; then
    chmod "$mode" "$dest" || die "could not set ${dest}'s mode"
    chown "root:${group}" "$dest" || die "could not set ${dest}'s owner"
    return 1
  fi
  install -D -m "$mode" -o root -g "$group" "$src" "$dest" || die "could not install ${dest}"
}

updates() {
  installed unattended-upgrades || apt_install unattended-upgrades
  cat >"${work}/52watchtower-bastion" <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
CONF
  put "${work}/52watchtower-bastion" /etc/apt/apt.conf.d/52watchtower-bastion 0644 root || true
}

guard_loaded() { nft list chain inet metadata_guard metadata >/dev/null 2>&1; }

# Whatever metadata does or doesn't answer, this ends with sshd up or with a
# reason it isn't: what's on disk from an earlier boot still applies.
guard() {
  local rc=0 retry=""
  installed nftables || apt_install --no-install-recommends nftables
  if mds instance/attributes/watchtower-ruleset >"${work}/ruleset.sh" && [[ -s "${work}/ruleset.sh" ]] && bash -n "${work}/ruleset.sh"; then
    put "${work}/ruleset.sh" "$RULESET_TOOL" 0755 root || true
  else
    warn "no usable watchtower-ruleset in metadata; using the one on disk"
  fi
  [[ -x "$RULESET_TOOL" ]] || die "no ${RULESET_TOOL}, so no way to load the guard"
  # Without its timer no trial starts, so a failure here costs only that.
  "$RULESET_TOOL" setup || warn "could not set up ${RULESET_TOOL}'s units"
  retry="$(mds instance/attributes/watchtower-nftables-retry 2>/dev/null || true)"
  if mds instance/attributes/watchtower-nftables >"${work}/nftables.conf" && [[ -s "${work}/nftables.conf" ]]; then
    "$RULESET_TOOL" apply "${work}/nftables.conf" "$retry" || rc=$?
  else
    warn "no watchtower-nftables in metadata; the ruleset on disk stays"
    "$RULESET_TOOL" apply || rc=$?
  fi
  case "$rc" in
    0) ;;
    "$RULESET_REBOOTING") log "rolling back: rebooting"; exit 0 ;;
    *) die "sshd may not run (see above), so nothing else does" ;;
  esac
}

# What scripts/bootstrap.sh waits for, in a guest attribute: any user can put a
# line on the console, and the guard keeps them from this. From here a stop can't
# break apt.
report_settled() {
  log "settled"
  curl -fsS -o /dev/null --max-time 5 --retry 2 --retry-connrefused -X PUT -H 'Metadata-Flavor: Google' \
    --data "$(date +%s)" "${MDS}/instance/guest-attributes/watchtower/settled" ||
    warn "could not put that in the guest attribute"
}

# check_peer <in> <out>: writes the config wg-quick may run, or fails saying
# why. Only its own words reach the output, never the config's. wg deletes all
# whitespace from a line, reads keys in any case and drops # comments, and
# wg-quick trims whatever its locale calls a space: so this reads a line as wg
# does, admits only the settings an agent needs, in their shape, and writes
# them out afresh. Nothing but what it checked reaches wg-quick, and no value
# wg would echo in an error message (into the journal, and so to Alloy).
check_peer() {
  awk -v cidr="$TUNNEL_CIDR" '
    function refuse(why) { print "peer config refused: " why >"/dev/stderr"; bad = 1 }
    # 32 bytes of base64, as wg reads a key.
    function wg_key(v) { return length(v) == 44 && v ~ /^[A-Za-z0-9+\/]+[AEIMQUYcgkosw048]=$/ }
    BEGIN {
      name["[interface]", "privatekey"] = "PrivateKey"
      name["[interface]", "address"] = "Address"
      name["[interface]", "mtu"] = "MTU"
      name["[peer]", "publickey"] = "PublicKey"
      name["[peer]", "presharedkey"] = "PresharedKey"
      name["[peer]", "allowedips"] = "AllowedIPs"
      name["[peer]", "endpoint"] = "Endpoint"
      name["[peer]", "persistentkeepalive"] = "PersistentKeepalive"
      net = cidr
      sub(/0\/24$/, "", net)
    }
    {
      line = $0
      sub(/#.*/, "", line)
      gsub(/[[:space:]]/, "", line)
      if (line == "") next
      if (substr(line, 1, 1) == "[") {
        section = tolower(line)
        if (section == "[interface]") { interfaces++; out[++n] = "[Interface]"; interface_at = n }
        else if (section == "[peer]") { peers++; out[++n] = "[Peer]"; peer_at = n }
        else { refuse("a section other than [Interface] and [Peer]"); section = "?" }
        next
      }
      eq = index(line, "=")
      if (eq == 0) { refuse("a line that is not key = value"); next }
      key = tolower(substr(line, 1, eq - 1))
      value = substr(line, eq + 1)
      if (key == "dns") next
      if (key ~ /^(preup|postup|predown|postdown|table|fwmark|saveconfig)$/) { refuse("a " key " line"); next }
      if (section == "") { refuse("a setting before any section"); next }
      # Not the key: a mistyped one may be the line holding the private key.
      if (!((section, key) in name)) { refuse("a setting its section may not have"); next }
      if (seen[key]++ == 1) refuse("more than one " key)
      if (key ~ /key$/ && !wg_key(value)) refuse("a " key " that is not a WireGuard key")
      if (key == "address" && (index(value, net) != 1 || substr(value, length(net) + 1) !~ /^[0-9]+\/32$/)) refuse("an Address other than one /32 in " cidr)
      if (key == "mtu" && value !~ /^[0-9]+$/) refuse("an MTU that is not a number")
      if (key == "persistentkeepalive" && value !~ /^[0-9]+$/) refuse("a PersistentKeepalive that is not a number")
      if (key == "endpoint" && value !~ /^[A-Za-z0-9.-]+:[0-9]+$/ && value !~ /^\[[0-9A-Fa-f:]+\]:[0-9]+$/) refuse("an Endpoint that is not host:port")
      if (key == "allowedips" && value != cidr) refuse("AllowedIPs other than " cidr)
      out[++n] = name[section, key] " = " value
    }
    END {
      if (interfaces != 1) refuse("not exactly one [Interface]")
      if (peers != 1) refuse("not exactly one [Peer]")
      if (!seen["privatekey"]) refuse("no PrivateKey")
      if (!seen["address"]) refuse("no Address")
      if (!seen["publickey"]) refuse("no PublicKey")
      if (!seen["endpoint"]) refuse("not exactly one Endpoint")
      if (!seen["allowedips"]) refuse("not exactly one AllowedIPs")
      if (bad) exit 1
      for (i = 1; i <= n; i++) {
        print out[i]
        if (i == interface_at && !seen["mtu"]) print "MTU = 1380"
        if (i == peer_at && !seen["persistentkeepalive"]) print "PersistentKeepalive = 25"
      }
    }' "$1" >"$2"
}

# fetch_peer <out>: the peer config into out, and peer_state says what came of
# it: have, none (the secret is missing or empty, the one thing that takes
# telemetry down) or unknown (anything else, which leaves it as it is: the
# network, a 5xx, the token, PERMISSION_DENIED, or a VM with no account yet).
fetch_peer() {
  local out=$1 code
  peer_state=unknown
  code="$(get "${MDS}/instance/service-accounts/default/email" "${work}/email" -H 'Metadata-Flavor: Google')"
  case "$code" in
    200) ;;
    404) warn "the VM has no service account; the tunnel stays as it is"; return 0 ;;
    *) warn "the metadata server answered ${code}; the tunnel stays as it is"; return 0 ;;
  esac
  code="$(get "${MDS}/instance/service-accounts/default/token" "${work}/token.json" -H 'Metadata-Flavor: Google')"
  if [[ "$code" != 200 ]]; then
    rm -f "${work}/token.json"
    warn "the metadata server answered ${code} for the token; the tunnel stays as it is"
    return 0
  fi
  # The token goes to curl on stdin, never on its command line: any user
  # here may read any process's arguments.
  code="$(jq -r '"header = \"Authorization: Bearer \(.access_token)\""' "${work}/token.json" |
    get "${SECRETS_API}/${PEER_SECRET}/versions/latest:access" "${work}/peer.json" -K -)" || code=000
  rm -f "${work}/token.json"
  case "$code" in
    200) ;;
    404) warn "${PEER_SECRET} has no version"; peer_state=none; return 0 ;;
    *) warn "Secret Manager answered ${code}; the tunnel stays as it is"; return 0 ;;
  esac
  if ! jq -r '.payload.data // empty' "${work}/peer.json" | base64 -d >"$out"; then
    rm -f "${work}/peer.json" "$out"
    warn "Secret Manager's answer doesn't parse; the tunnel stays as it is"
    return 0
  fi
  rm -f "${work}/peer.json"
  if [[ -s "$out" ]]; then
    peer_state=have
  else
    warn "${PEER_SECRET}'s latest version is empty"
    peer_state=none
  fi
}

# Stops and disables the tunnel and Alloy, and removes their config. Alloy's
# drop-in stays: without the tunnel's config it keeps Alloy from starting at
# all, even on the package's own.
teardown() {
  local unit
  for unit in alloy.service wg-quick@wg-watchtower.service; do
    if systemctl cat "$unit" >/dev/null 2>&1; then
      systemctl disable --now --quiet "$unit"
      # Alloy outlasts its stop timeout when it can't flush: not a failure.
      systemctl reset-failed "$unit" 2>/dev/null || true
    fi
  done
  rm -f "$WG_CONF" "$ALLOY_CONFIG"
}

alloy_installed() {
  # shellcheck disable=SC2016 # dpkg-query's format, not the shell's
  [[ "$(dpkg-query -W -f '${db:Status-Status} ${Version}' alloy 2>/dev/null || true)" == "installed ${ALLOY_VERSION}-1" ]]
}

# Alloy's .deb: the release's own, checked against its pinned sha256. No
# third-party apt repository on a break-glass host.
alloy_install() {
  local deb="${work}/alloy.deb"
  [[ "$(dpkg --print-architecture)" == amd64 ]] || die "no pinned Alloy .deb for $(dpkg --print-architecture)"
  curl -fsSL --retry 5 --max-time 600 -o "$deb" \
    "https://github.com/grafana/alloy/releases/download/v${ALLOY_VERSION}/alloy-${ALLOY_VERSION}-1.amd64.deb"
  echo "${ALLOY_DEB_SHA256}  ${deb}" | sha256sum -c --quiet -
  dpkg_heal
  apt_get install -y --no-install-recommends "$deb"
}

# Warn only: Alloy's readiness, then the tunnel's handshake.
health() {
  local i hs=0
  for i in $(seq 12); do
    curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:12345/-/ready 2>/dev/null && break
    [[ "$i" -lt 12 ]] || warn "Alloy is not ready after a minute"
    sleep 5
  done
  for i in $(seq 24); do
    # The time only: the first field is the server's public key.
    hs="$(wg show wg-watchtower latest-handshakes 2>/dev/null | awk '{ print $2; exit }')" || hs=0
    [[ "${hs:-0}" -gt 0 ]] && break
    sleep 5
  done
  if [[ "${hs:-0}" -gt 0 ]]; then
    log "the tunnel is up"
  else
    warn "no WireGuard handshake within 2 minutes"
  fi
}

main() {
  local peer_changed="" alloy_changed=""
  umask 077
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT

  guard
  if guard_loaded; then
    log "metadata guard loaded"
  else
    warn "no metadata guard: this VM has no account, so no token to guard"
  fi

  updates
  installed wireguard-tools jq || apt_install --no-install-recommends wireguard-tools jq
  report_settled
  fetch_peer "${work}/peer.in"
  case "$peer_state" in
    have) ;;
    none)
      teardown
      warn "no agent peer: the tunnel and Alloy are off"
      return 0
      ;;
    *) return 0 ;;
  esac
  if ! check_peer "${work}/peer.in" "${work}/peer.conf"; then
    rm -f "${work}/peer.in" "${work}/peer.conf"
    die "the agent peer failed its checks: the tunnel and Alloy stay as they are"
  fi
  rm -f "${work}/peer.in"
  put "${work}/peer.conf" "$WG_CONF" 0600 root && peer_changed=1
  rm -f "${work}/peer.conf"

  if ! alloy_installed; then
    alloy_install
    alloy_changed=1
  fi
  mds instance/attributes/watchtower-alloy >"${work}/bastion.alloy"
  put "${work}/bastion.alloy" "$ALLOY_CONFIG" 0640 alloy && alloy_changed=1
  cat >"${work}/alloy-dropin.conf" <<'UNIT'
# config/bastion/startup.sh: watchtower's config, with the tunnel only.
[Unit]
After=wg-quick@wg-watchtower.service
Wants=wg-quick@wg-watchtower.service
ConditionPathExists=/etc/wireguard/wg-watchtower.conf

[Service]
# A 1 GB host: an OOM kills Alloy, never sshd.
MemoryMax=192M
Environment=GOMEMLIMIT=150MiB
# Its UI on loopback only, no usage reports.
ExecStart=
ExecStart=/usr/bin/alloy run --server.http.listen-addr=127.0.0.1:12345 --disable-reporting --storage.path=/var/lib/alloy/data /etc/alloy/bastion.alloy
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/alloy
ProtectHome=yes
PrivateTmp=yes
UNIT
  put "${work}/alloy-dropin.conf" "$ALLOY_DROPIN" 0644 root && alloy_changed=1
  systemctl daemon-reload

  systemctl enable --quiet wg-quick@wg-watchtower.service alloy.service
  if [[ -n "$peer_changed" ]]; then
    systemctl restart wg-quick@wg-watchtower.service
  else
    systemctl start wg-quick@wg-watchtower.service
  fi
  if [[ -n "$alloy_changed" ]]; then
    systemctl restart alloy.service
  else
    systemctl start alloy.service
  fi
  log "the tunnel and Alloy are on${peer_changed:+ (new peer config)}${alloy_changed:+ (new Alloy or config)}"
  health
}

# scripts/check-bastion.sh sources this for its functions.
[[ -n "${BASTION_STARTUP_LIB:-}" ]] || main "$@"
