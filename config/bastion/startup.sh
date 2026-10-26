#!/bin/bash
# The break-glass bastion's startup script. GCE runs it as root at every
# boot; scripts/bootstrap.sh (step 7) puts it in the VM's metadata with the
# two files it reads from there, watchtower-nftables (nftables.conf here) and
# watchtower-alloy (config/alloy/bastion.alloy). Idempotent, and it never
# prints the peer config or the VM's token: its output goes to the serial
# console and the journal, which Alloy ships.
#
#   1. Security updates every day, rebooting at 04:00 UTC when one needs it.
#   2. The metadata guard (nftables.conf): only root reaches the metadata
#      server, so only root can use the VM's token. Nothing else runs if it
#      doesn't load.
#   3. Its agent peer (docs/client-telemetry.md), read from Secret Manager
#      with that token, checked and normalised, as wg-quick@wg-watchtower.
#      None to read (no service account, no version or an empty one): the
#      tunnel and Alloy are stopped and disabled, and their config removed.
#      A config that fails the checks goes the same way, as an error.
#   4. Grafana Alloy from the release's .deb, pinned by sha256, run with the
#      config from metadata, capped at 192 MiB, and only with the tunnel.
#   5. Warns, never fails, when Alloy isn't ready or the tunnel has no
#      handshake within 2 minutes.
#
# scripts/check-bastion.sh tests the peer checks and the guard.

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

log() { printf 'bastion: %s\n' "$*"; }
warn() { printf 'bastion: warning: %s\n' "$*" >&2; }
die() { printf 'bastion: error: %s\n' "$*" >&2; exit 1; }

# The daily upgrade may hold dpkg's lock at boot: wait for it. With the usual
# umask, not this script's.
apt_get() { (umask 022 && apt-get -q -o DPkg::Lock::Timeout=600 "$@"); }

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
  dpkg -s unattended-upgrades >/dev/null 2>&1 || { apt_get update && apt_get install -y unattended-upgrades; }
  cat >"${work}/52watchtower-bastion" <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
CONF
  put "${work}/52watchtower-bastion" /etc/apt/apt.conf.d/52watchtower-bastion 0644 root || true
}

guard() {
  command -v nft >/dev/null || { apt_get update && apt_get install -y --no-install-recommends nftables; }
  mds instance/attributes/watchtower-nftables >"${work}/nftables.conf"
  nft --check --file "${work}/nftables.conf"
  put "${work}/nftables.conf" /etc/nftables.conf 0644 root || true
  systemctl enable --quiet nftables.service
  systemctl reload-or-restart nftables.service
  nft list chain inet metadata_guard metadata >/dev/null || die "the metadata guard did not load"
}

# check_peer <in> <out>: writes the config wg-quick may run, normalised, or
# fails saying why. Only its own words reach the output, never the
# config's. wg-quick reads keys in any case and drops # comments; so does
# this, and it keeps no comment or blank line.
check_peer() {
  awk -v cidr="$TUNNEL_CIDR" '
    function refuse(why) { print "peer config refused: " why >"/dev/stderr"; bad = 1 }
    {
      line = $0
      sub(/\r$/, "", line)
      sub(/#.*/, "", line)
      gsub(/^[ \t]+|[ \t]+$/, "", line)
      if (line == "") next
      if (substr(line, 1, 1) == "[") {
        section = tolower(line)
        if (section == "[interface]") { interfaces++; interface_at = n + 1 }
        else if (section == "[peer]") { peers++; peer_at = n + 1 }
        else refuse("a section other than [Interface] and [Peer]")
        out[++n] = line
        next
      }
      eq = index(line, "=")
      if (eq == 0) { refuse("a line that is not key = value"); next }
      key = tolower(substr(line, 1, eq - 1))
      sub(/[ \t]+$/, "", key)
      value = substr(line, eq + 1)
      gsub(/[ \t]/, "", value)
      if (key ~ /^(preup|postup|predown|postdown|table|fwmark|saveconfig)$/) refuse("a " key " line")
      if (key == "dns") next
      if (section == "") refuse("a setting before any section")
      if (key == "mtu" && section == "[interface]") mtu = 1
      if (key == "persistentkeepalive" && section == "[peer]") keepalive = 1
      if (key == "endpoint") { endpoints++; if (section != "[peer]") refuse("an Endpoint outside [Peer]") }
      if (key == "allowedips") {
        allowed++
        if (section != "[peer]" || value != cidr) refuse("AllowedIPs other than " cidr)
      }
      out[++n] = line
    }
    END {
      if (interfaces != 1) refuse("not exactly one [Interface]")
      if (peers != 1) refuse("not exactly one [Peer]")
      if (endpoints != 1) refuse("not exactly one Endpoint")
      if (allowed != 1) refuse("not exactly one AllowedIPs")
      if (bad) exit 1
      for (i = 1; i <= n; i++) {
        print out[i]
        if (i == interface_at && !mtu) print "MTU = 1380"
        if (i == peer_at && !keepalive) print "PersistentKeepalive = 25"
      }
    }' "$1" >"$2"
}

# fetch_peer <out>: the peer config into out, and have_peer set; have_peer
# empty when there is none to have. Dies, leaving the tunnel as it is, when
# Google didn't answer.
fetch_peer() {
  local out=$1 code
  have_peer=""
  code="$(get "${MDS}/instance/service-accounts/default/email" "${work}/email" -H 'Metadata-Flavor: Google')"
  case "$code" in
    200) ;;
    404) warn "the VM has no service account"; return 0 ;;
    *) die "the metadata server answered ${code}; the tunnel stays as it was" ;;
  esac
  mds instance/service-accounts/default/token >"${work}/token.json"
  # The token goes to curl on stdin, never on its command line: any user
  # here may read any process's arguments.
  code="$(jq -r '"header = \"Authorization: Bearer \(.access_token)\""' "${work}/token.json" |
    get "${SECRETS_API}/${PEER_SECRET}/versions/latest:access" "${work}/peer.json" -K -)"
  rm -f "${work}/token.json"
  case "$code" in
    200) ;;
    404) warn "${PEER_SECRET} has no version"; return 0 ;;
    *) die "Secret Manager answered ${code}; the tunnel stays as it was" ;;
  esac
  jq -r '.payload.data // empty' "${work}/peer.json" | base64 -d >"$out"
  rm -f "${work}/peer.json"
  if [[ -s "$out" ]]; then
    have_peer=1
  else
    warn "${PEER_SECRET}'s latest version is empty"
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
  [[ "$(dpkg-query -W -f '${Version}' alloy 2>/dev/null || true)" == "${ALLOY_VERSION}-1" ]]
}

# Alloy's .deb: the release's own, checked against its pinned sha256. No
# third-party apt repository on a break-glass host.
alloy_install() {
  local deb="${work}/alloy.deb"
  [[ "$(dpkg --print-architecture)" == amd64 ]] || die "no pinned Alloy .deb for $(dpkg --print-architecture)"
  curl -fsSL --retry 5 --max-time 600 -o "$deb" \
    "https://github.com/grafana/alloy/releases/download/v${ALLOY_VERSION}/alloy-${ALLOY_VERSION}-1.amd64.deb"
  echo "${ALLOY_DEB_SHA256}  ${deb}" | sha256sum -c --quiet -
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

  updates
  guard
  log "metadata guard loaded"

  if ! dpkg -s wireguard-tools jq >/dev/null 2>&1; then
    apt_get update
    apt_get install -y --no-install-recommends wireguard-tools jq
  fi
  fetch_peer "${work}/peer.in"
  if [[ -z "$have_peer" ]]; then
    teardown
    warn "no agent peer: the tunnel and Alloy are off"
    return 0
  fi
  if ! check_peer "${work}/peer.in" "${work}/peer.conf"; then
    teardown
    die "the agent peer failed its checks: the tunnel and Alloy are off"
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
