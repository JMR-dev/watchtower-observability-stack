#!/bin/bash
# The break-glass bastion's startup script. GCE runs it as root at every
# boot; scripts/bootstrap.sh (step 7) puts it in the VM's metadata with the
# three files it reads from there, watchtower-nftables (nftables.conf here),
# watchtower-ruleset (ruleset.sh here) and watchtower-alloy
# (config/alloy/bastion.alloy). Idempotent, and it never prints the peer config
# or the VM's token: its output goes to the serial console and the journal,
# which Alloy ships.
#
#   0. Unprivileged user namespaces off, for good (a file in /etc/sysctl.d), so
#      no user gets one before this boot's sshd: users have no need of them.
#   1. The metadata guard (nftables.conf): only root reaches the metadata
#      server, so only root can use the VM's token. First, since sshd waits
#      on it. A new ruleset goes on under a 10-minute rollback that a login
#      cancels, and sshd runs only with the guard loaded or on a VM with no
#      token (ruleset.sh). Nothing else runs if sshd may not. A new ruleset.sh
#      goes in only once it passes a self-check, and one that then fails at a
#      boot gives way to the last good copy.
#   2. Security updates every day, rebooting at 04:00 UTC when one needs it.
#   3. Says so in a guest attribute once apt is done: scripts/bootstrap.sh stops
#      the VM for its account only after that.
#   4. Pings its Healthchecks.io check, once the guard is loaded and sshd is
#      active, so a bastion that didn't come back from a reboot gets noticed.
#      A timer does the same at 05:00 UTC every day, as the VM reboots only
#      when an update needs it and a check pinged only at boot would have
#      nothing to go overdue by: this file, kept on disk, run with `ping`. No
#      failure here touches anything else, and the URL never reaches an argument
#      or any output.
#   5. Its agent peer (docs/client-telemetry.md), read from Secret Manager
#      with that token, checked and normalised, as wg-quick@wg-watchtower. A
#      missing or empty secret, and nothing else, takes the tunnel and Alloy
#      down: stopped and disabled, and their config removed. Any other failure
#      to read it, or a config that fails the checks, warns and leaves them
#      running as they are. Revoking a peer is done by deleting its client in
#      wg-easy.
#   6. Grafana Alloy from the release's .deb, pinned by sha256, run with the
#      config from metadata, capped at 192 MiB, and only with the tunnel.
#   7. Warns, never fails, when Alloy isn't ready or the tunnel has no
#      handshake within 2 minutes.
#
# scripts/check-bastion.sh tests the peer checks, the ping, the guard and the
# rollback. When SSH is gone, config/bastion/recovery.sh takes this one's place
# in metadata for a boot (docs/runbook.md, "The bastion with SSH gone").

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

MDS="http://169.254.169.254/computeMetadata/v1"
SECRETS_API="https://secretmanager.googleapis.com/v1"
# The bastion's agent peer, the one secret its service account may read. A
# Go test keeps it equal to names.AgentPeers.
PEER_SECRET="projects/watchtower-observe/secrets/wireguard-bastion-peer"
# Its Healthchecks.io check's ping URL (scripts/healthchecks.sh), the other one.
# A Go test keeps it equal to names.SecretHealthchecksBastionURL.
PING_SECRET="projects/watchtower-observe/secrets/healthchecks-bastion-url"
# This file, kept on disk for the daily ping.
STARTUP_TOOL="/usr/local/sbin/watchtower-startup"
TUNNEL_CIDR="10.8.0.0/24"
WG_CONF="/etc/wireguard/wg-watchtower.conf"
ALLOY_VERSION="1.21.3"
# alloy-1.21.3-1.amd64.deb, from the release's SHA256SUMS.
ALLOY_DEB_SHA256="dbbd705de8ab37dec0cbd6361a3fc7e754d6b2854b57ce672a83e6366199ba73"
ALLOY_CONFIG="/etc/alloy/bastion.alloy"
ALLOY_DROPIN="/etc/systemd/system/alloy.service.d/watchtower.conf"
RULESET_TOOL="/usr/local/sbin/watchtower-ruleset"
# The last copy of it that passed its self-check and brought sshd up through its gate.
# recovery.sh names it too.
TOOL_LAST_GOOD="/usr/local/sbin/watchtower-ruleset.last-good"
# ruleset.sh's record of a trial that is pending: nothing is promoted while it's there.
PENDING_TRIAL="/var/lib/watchtower-bastion/pending"
# ruleset.sh's marker that its apply went through to its end with its ruleset
# confirmed, as `confirmed <sha256 of the tool>` (its APPLIED, written by cmd_apply
# alone), cleared before each apply here: the apply's own proof for tool_proved.
RULESET_APPLIED="/run/watchtower-ruleset.applied"
# The watchtower/tool word report_tool said at this boot, kept for ruleset.sh to say
# again after a login: root's alone, and only once this boot's apply ended well.
TOOL_WORD="/run/watchtower-ruleset.tool"
# 404 here means a VM with no account, so no token to guard. recovery.sh names it too.
ACCOUNT_URL="${MDS}/instance/service-accounts/default/email"
# How long the tool's setup or apply may take at a boot before it's stopped and, for
# apply, the last good copy takes over; and the self-check of a new tool.
TOOL_TIMEOUT="5m"
SELF_CHECK_TIMEOUT="2m"
# ruleset.sh's exit status when it rolled back and is rebooting.
RULESET_REBOOTING=75
# This boot's run nonce, from metadata, for ruleset.sh's guest attributes and the
# settled one: root's alone, in /run, so gone at the next boot.
RUN_NONCE="/run/watchtower-run-nonce"
# Unprivileged user namespaces, off: Debian's own knob, and where it's set for good.
USERNS_CONF="/etc/sysctl.d/90-watchtower-userns.conf"
USERNS_KNOB="/proc/sys/kernel/unprivileged_userns_clone"

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

# mds_file <path> <file>: into a file by name. curl starts a named file over on a
# retry. On stdout, a first try that stalled leaves its part, with the whole after it,
# and that can still parse.
mds_file() { curl -fsS --retry 5 --retry-connrefused --max-time 30 -H 'Metadata-Flavor: Google' -o "$2" "${MDS}/$1"; }

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
# they differ; true when it did. Whole or not at all: a temp file beside it, moved
# over it once it's all there, as a tool cut short by a full disk or a reset would
# keep sshd down (its gate is the tool). What's executable here is a script, so it
# has to parse too. Called as a condition, where set -e is off, so every failure
# dies by hand.
put() {
  local src=$1 dest=$2 mode=$3 group=$4 tmp="${2}.tmp"
  if [[ -f "$dest" ]] && cmp -s "$src" "$dest"; then
    chmod "$mode" "$dest" || die "could not set ${dest}'s mode"
    chown "root:${group}" "$dest" || die "could not set ${dest}'s owner"
    return 1
  fi
  if ! install -D -m "$mode" -o root -g "$group" "$src" "$tmp"; then
    rm -f "$tmp"
    die "could not write ${dest}; what was there stays"
  fi
  if [[ "$mode" == 0755 ]] && ! bash -n "$tmp"; then
    rm -f "$tmp"
    die "${dest} wouldn't parse; what was there stays"
  fi
  # On disk before the name moves, so a reset can't leave the name on nothing.
  sync "$tmp" || true
  if ! mv -f "$tmp" "$dest"; then
    rm -f "$tmp"
    die "could not put ${dest} in place; what was there stays"
  fi
}

# Unprivileged user namespaces off (the owner's decision, 2026-11-04): kernel attack
# surface that no user here needs. Debian's own knob, which Debian 13's kernel has,
# stops users alone: root and PID 1 still make them, as systemd does for
# chrony-wait.service's and fstrim.service's PrivateUsers=, and as nothing else here
# needs (sshd, OS Login, wg-quick, Alloy, and the guard's `unshare --net`, which is
# root's and asks for no user namespace). user.max_user_namespaces=0 would stop those
# two units as well. systemd-sysctl applies the file at every later boot, before any
# login; this applies it now. Warns, never fails: a kernel without the knob keeps
# sshd up.
#
# What came of it is kept in userns_state, off or on, for report_userns to tell
# bootstrap, which warns when it's on.
userns_off() {
  userns_state=on
  printf '%s\n' '# config/bastion/startup.sh: user namespaces for root alone.' \
    'kernel.unprivileged_userns_clone = 0' >"${work}/userns.conf"
  # A subshell, as put dies on a failure.
  (put "${work}/userns.conf" "$USERNS_CONF" 0644 root) || true
  sysctl -q -p "$USERNS_CONF" >/dev/null 2>&1 || true
  if [[ "$(cat "$USERNS_KNOB" 2>/dev/null)" == 0 ]]; then
    userns_state=off
    log "unprivileged user namespaces: off"
  else
    warn "unprivileged user namespaces may be on: ${USERNS_KNOB} isn't 0"
  fi
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

# The guard in the kernel, by its rules: the tool's word, as sshd's gate goes by it.
guard_loaded() { "$RULESET_TOOL" loaded >/dev/null 2>&1; }

# A user's connection to the metadata server is refused here and now. Asks nothing
# of the server, and with the network up, as it is by the time anything pings.
guard_refuses_users() { "$RULESET_TOOL" refuses-users >/dev/null 2>&1; }

# The ruleset's tool, and the last good copy of it (the owner's decision, 2026-11-04).
# A new ruleset goes on under the dead man's switch, but a bug in the tool itself
# would have no way back, and sshd's gate is that tool. So:
#   - a tool from metadata goes in only once it has passed its self-check
#     (tool_self_check), and one that fails it never runs, even with no other tool;
#   - a tool that has brought sshd up through its gate at a boot with no ruleset trial
#     pending, and passes the self-check, becomes the last good copy (promote_tool);
#   - a tool that fails at a boot, or takes longer than TOOL_TIMEOUT there, gives way
#     to the last good copy, which then has the boot to itself (fall_back). sshd still
#     starts only through the gate.
# recovery.sh uses the last good copy the same way.

# tool_whole <file>: executable, parses, and ends as the tool ends: a file cut at a
# line can parse and do nothing, which sshd's gate would take for a yes.
tool_whole() {
  # shellcheck disable=SC2016 # the tool's own last line, as written
  [[ -x "$1" ]] && bash -n "$1" 2>/dev/null && [[ "$(tail -n 1 "$1")" == 'main "$@"' ]]
}

# tool_in_namespace <tool> <floor file>: run by tool_self_check, alone in a network
# namespace of its own. What sshd's gate and a rollback rely on, each in turn: no
# rules is no guard, and no guard with the metadata server out of reach keeps sshd
# down; its own floor, loaded, guards (root reaches the server's addresses, a user
# doesn't), and with it on, sshd may run.
# shellcheck disable=SC2329 # run by tool_self_check, through declare -f
tool_in_namespace() {
  local tool=$1 floor=$2
  nft --check --file "$floor" || { warn "its floor doesn't pass nft --check"; return 1; }
  if "$tool" loaded >/dev/null 2>&1; then warn "it takes an empty ruleset for a guard"; return 1; fi
  if "$tool" gate >/dev/null 2>&1; then warn "its gate lets sshd run with no guard"; return 1; fi
  "$tool" probe "$floor" >/dev/null 2>&1 || { warn "its floor doesn't guard"; return 1; }
  "$tool" gate >/dev/null 2>&1 || { warn "its gate keeps sshd down with its floor on"; return 1; }
}

# tool_self_check <tool>: whole, and its floor rendered and checked as above, in a
# network namespace that is gone when it ends, so nothing it loads reaches the live
# kernel. Asked by this script rather than of the tool about itself, through the
# commands the units and sshd's gate use. Says why it failed.
tool_self_check() {
  local tool=$1 floor="${work}/floor.nft" rc=0
  tool_whole "$tool" || { warn "${tool} is cut short or won't parse"; return 1; }
  timeout -k 10s "$SELF_CHECK_TIMEOUT" "$tool" floor-rules >"$floor" 2>/dev/null || { warn "${tool} won't render its floor"; return 1; }
  timeout -k 10s "$SELF_CHECK_TIMEOUT" \
    unshare --net bash -c "$(declare -f warn tool_in_namespace); tool_in_namespace \"\$@\"" bash "$tool" "$floor" || rc=$?
  [[ "$rc" != 124 && "$rc" != 137 ]] || warn "its self-check took longer than ${SELF_CHECK_TIMEOUT}, and was stopped"
  return "$rc"
}

# take_tool <file>: the tool from metadata, in place of the one on disk, if it passed
# its self-check. Whole or not at all: a disk that won't take it leaves the old one.
take_tool() {
  [[ -f "$RULESET_TOOL" ]] && cmp -s "$1" "$RULESET_TOOL" && return 0
  chmod 0700 "$1"
  if ! tool_self_check "$1"; then
    warn "the watchtower-ruleset in metadata failed its self-check, so it doesn't go in"
    return 0
  fi
  # A subshell, as put dies on a failure.
  (put "$1" "$RULESET_TOOL" 0755 root) || true
}

# restore_last_good: the last good copy back, when the tool on disk is gone or cut
# short. True when the tool is whole now.
restore_last_good() {
  tool_whole "$TOOL_LAST_GOOD" || return 1
  warn "${RULESET_TOOL} is missing or cut short: putting back its last good copy"
  (put "$TOOL_LAST_GOOD" "$RULESET_TOOL" 0755 root) || true
  tool_whole "$RULESET_TOOL"
}

# fall_back: the last good copy in place of a tool that failed at this boot, if there's
# one that differs. True when it's in place.
fall_back() {
  tool_whole "$TOOL_LAST_GOOD" || return 1
  [[ -f "$RULESET_TOOL" ]] && cmp -s "$TOOL_LAST_GOOD" "$RULESET_TOOL" && return 1
  warn "${RULESET_TOOL} failed at this boot: falling back to its last good copy"
  (put "$TOOL_LAST_GOOD" "$RULESET_TOOL" 0755 root) || true
  cmp -s "$TOOL_LAST_GOOD" "$RULESET_TOOL"
}

# no_account: the metadata server says this VM has no account, so no token to guard.
# Only a 404 says so: anything else may be a VM with a token.
no_account() {
  [[ "$(get "$ACCOUNT_URL" "${work}/account-email" -H 'Metadata-Flavor: Google')" == 404 ]]
}

# sshd_up_unguarded: sshd is active, the guard isn't in the kernel (by its name, as
# there may be no tool to ask by its rules), and the VM may have an account (the
# metadata server doesn't say 404). recovery.sh has the same function, word for word,
# and scripts/check-bastion.sh keeps them equal.
sshd_up_unguarded() {
  local code
  systemctl is-active --quiet ssh.service || return 1
  ! nft list chain inet metadata_guard metadata >/dev/null 2>&1 || return 1
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --retry 2 --retry-connrefused \
    -H 'Metadata-Flavor: Google' "$ACCOUNT_URL" 2>/dev/null || true)"
  [[ "$code" != 404 ]]
}

# stop_ungated_sshd: what a boot leaves with the tool and sshd's drop-in both gone, and
# no tool to restore: systemd started sshd before this script, and nothing gated it.
# Stopped, as nothing may run with a token and no guard, as recovery.sh does.
stop_ungated_sshd() {
  sshd_up_unguarded || return 0
  warn "sshd is up with no guard, on a VM that may have an account: stopping it"
  systemctl stop ssh.service || warn "could not stop sshd"
}

# tool_proved: what this boot's apply has shown of the tool, beyond its self-check:
# that apply itself went through to its end with its ruleset confirmed (its marker,
# which run_tool clears before it and cmd_apply alone writes, for this tool's own code;
# sshd up and the guard on may be the boot's doing, from the tool before, and
# ruleset.sh's word on its ruleset is a login's confirm's too, so none of those proves
# anything here); sshd active, through the gate as it stands now (the guard in the
# kernel, or no account and so no token); and no ruleset trial pending, whose
# confirmation or rollback the tool hasn't run yet. A tool whose apply ends at once,
# saying nothing, shows none of it, even with a login confirming meanwhile. Says why
# not.
tool_proved() {
  local sha
  if [[ -e "$PENDING_TRIAL" ]]; then
    warn "a ruleset trial is pending, so ${RULESET_TOOL} isn't kept as the last good copy before a boot after it"
    return 1
  fi
  sha="$(sha256sum <"$RULESET_TOOL" 2>/dev/null | cut -d' ' -f1)" || sha=""
  if [[ -z "$sha" || "$(cat "$RULESET_APPLIED" 2>/dev/null)" != "confirmed ${sha}" ]]; then
    warn "${RULESET_TOOL}'s apply didn't end with its ruleset confirmed at this boot, so it isn't kept as the last good copy"
    return 1
  fi
  if ! systemctl is-active --quiet ssh.service; then
    warn "sshd isn't active, so ${RULESET_TOOL} isn't kept as the last good copy"
    return 1
  fi
  if ! guard_loaded && ! no_account; then
    warn "no guard in the kernel, on a VM that may have an account, so ${RULESET_TOOL} isn't kept as the last good copy"
    return 1
  fi
}

# promote_tool: the tool becomes the last good copy once this boot has shown it works
# (tool_proved) and it has passed the self-check too. Never fails. With a trial pending
# nothing is promoted, so a first install has no last good copy until a boot after its
# trial has ended.
promote_tool() {
  [[ -f "$TOOL_LAST_GOOD" ]] && cmp -s "$RULESET_TOOL" "$TOOL_LAST_GOOD" && return 0
  tool_proved || return 0
  if ! tool_self_check "$RULESET_TOOL"; then
    warn "${RULESET_TOOL} failed its self-check, so it isn't kept as the last good copy"
    return 0
  fi
  (put "$RULESET_TOOL" "$TOOL_LAST_GOOD" 0755 root) || warn "could not keep the last good copy of ${RULESET_TOOL}"
}

# run_tool <ruleset file, or nothing> <retry>: its units, then the ruleset, ending with
# sshd up or a reason it isn't. apply's exit status. Each within TOOL_TIMEOUT: a tool
# that hangs at a boot would otherwise hold the boot, and the lock the rollback needs.
# timeout ends the tool's whole process group, so nothing of it keeps that lock.
run_tool() {
  local rc=0
  # Only this apply's marker counts for tool_proved.
  rm -f "$RULESET_APPLIED"
  # Without its timer no trial starts, so a failure here costs only that.
  timeout -k 10s "$TOOL_TIMEOUT" "$RULESET_TOOL" setup || warn "could not set up ${RULESET_TOOL}'s units"
  if [[ -n "$1" ]]; then
    timeout -k 10s "$TOOL_TIMEOUT" "$RULESET_TOOL" apply "$1" "$2" || rc=$?
  else
    warn "no watchtower-nftables in metadata; the ruleset on disk stays"
    timeout -k 10s "$TOOL_TIMEOUT" "$RULESET_TOOL" apply || rc=$?
  fi
  [[ "$rc" != 124 && "$rc" != 137 ]] || warn "${RULESET_TOOL} apply took longer than ${TOOL_TIMEOUT}, and was stopped"
  return "$rc"
}

# keep_run_nonce: the run nonce scripts/bootstrap.sh put in metadata while the VM was
# stopped (the owner's decision, 2026-11-04), kept for root alone, for every guest
# attribute this boot writes: bootstrap counts only values with its own. None, or not
# one: no file, and they carry "-". 0600 whatever umask this runs with, and never by
# writing into a file that was there.
keep_run_nonce() {
  local nonce
  nonce="$(mds instance/attributes/watchtower-run-nonce 2>/dev/null || true)"
  rm -f "$RUN_NONCE"
  if [[ "$nonce" =~ ^[0-9a-f]{32}$ ]]; then
    (umask 077 && printf '%s\n' "$nonce" >"$RUN_NONCE") || warn "could not keep this boot's run nonce"
  fi
}

# This boot's run nonce, or "-": ruleset.sh's run_nonce.
run_nonce() {
  local nonce
  nonce="$(cat "$RUN_NONCE" 2>/dev/null)" || nonce=""
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || nonce=-
  printf '%s' "$nonce"
}

# Whatever metadata does or doesn't answer, this ends with sshd up or with a
# reason it isn't: what's on disk from an earlier boot still applies. It never starts
# sshd itself: only the tool does, through its gate.
guard() {
  local rc=0 retry="" ruleset=""
  installed nftables || apt_install --no-install-recommends nftables
  keep_run_nonce
  if mds_file instance/attributes/watchtower-ruleset "${work}/ruleset.sh" && [[ -s "${work}/ruleset.sh" ]]; then
    take_tool "${work}/ruleset.sh"
  else
    warn "no watchtower-ruleset in metadata; using the one on disk"
  fi
  # Nothing here then asks for sshd: it stays as the boot left it. That's down, at a
  # boot with sshd's drop-in, whose gate needs the tool; and up, ungated, on a first
  # install or a new VM, which has no drop-in yet and no account, so no token to guard.
  # Up with no guard on a VM that may have an account, with the drop-in gone too, it's
  # stopped.
  if ! tool_whole "$RULESET_TOOL" && ! restore_last_good; then
    stop_ungated_sshd
    die "no usable ${RULESET_TOOL} and no last good copy, so no way to load the guard, and nothing here asks for sshd: it stays as the boot left it, unless it was up with no guard on a VM that may have an account"
  fi
  retry="$(mds instance/attributes/watchtower-nftables-retry 2>/dev/null || true)"
  if mds_file instance/attributes/watchtower-nftables "${work}/nftables.conf" && [[ -s "${work}/nftables.conf" ]]; then
    ruleset="${work}/nftables.conf"
  fi
  run_tool "$ruleset" "$retry" || rc=$?
  if [[ "$rc" != 0 && "$rc" != "$RULESET_REBOOTING" ]] && fall_back; then
    rc=0
    run_tool "$ruleset" "$retry" || rc=$?
  fi
  case "$rc" in
    0) promote_tool ;;
    "$RULESET_REBOOTING") log "rolling back: rebooting"; exit 0 ;;
    *) die "sshd may not run (see above), so nothing else does" ;;
  esac
}

# word_of <value>: `<value> boot <boot id> run <run nonce>`, which is how bootstrap
# reads the guest attributes.
word_of() { printf '%s boot %s run %s' "$1" "$(cat /proc/sys/kernel/random/boot_id)" "$(run_nonce)"; }

# put_value <key> <value>: the guest attribute watchtower/<key>, as it is.
put_value() {
  curl -fsS -o /dev/null --max-time 5 --retry 2 --retry-connrefused -X PUT -H 'Metadata-Flavor: Google' \
    --data "$2" "${MDS}/instance/guest-attributes/watchtower/$1"
}

# put_word <key> <value>: the guest attribute watchtower/<key>, as word_of says it.
put_word() { put_value "$1" "$(word_of "$2")"; }

# Which tool this boot runs, in a guest attribute, by its sha256: bootstrap reports
# success only if it's the one it put in metadata, so a tool that failed its
# self-check, or gave way to the last good copy, can't pass unseen. Called only once
# guard() has returned, so this boot's apply ended well. The word is kept in TOOL_WORD
# too, root's alone, for ruleset.sh to say again with a login if this PUT is lost; with
# no such file it says nothing, so a login can't vouch for a tool whose apply failed.
report_tool() {
  local sha word
  sha="$(sha256sum <"$RULESET_TOOL" 2>/dev/null | cut -d' ' -f1)" || sha=""
  [[ -n "$sha" ]] || { warn "could not read ${RULESET_TOOL} to report it"; return 0; }
  word="$(word_of "$sha")"
  rm -f "$TOOL_WORD"
  (umask 077 && printf '%s\n' "$word" >"$TOOL_WORD") || warn "could not keep the tool's word for a login to say again"
  put_value tool "$word" || warn "could not put the tool in the guest attribute"
}

# Whether unprivileged user namespaces are off at this boot (userns_off), in a guest
# attribute: bootstrap warns when they're on, as the journal alone would say it to
# no one.
report_userns() {
  put_word userns "${userns_state:-on}" || warn "could not put user namespaces in the guest attribute"
}

# What scripts/bootstrap.sh waits for, in a guest attribute: any user can put a
# line on the console, and the guard keeps them from this. From here a stop can't
# break apt.
report_settled() {
  log "settled"
  curl -fsS -o /dev/null --max-time 5 --retry 2 --retry-connrefused -X PUT -H 'Metadata-Flavor: Google' \
    --data "$(cat /proc/sys/kernel/random/boot_id) run $(run_nonce)" "${MDS}/instance/guest-attributes/watchtower/settled" ||
    warn "could not put that in the guest attribute"
}

# latest_secret <secret> <token.json> <out>: Secret Manager's answer for the
# secret's latest version into out, read with the token, which it then removes;
# prints the HTTP status. The token goes to curl on stdin, never on its command
# line: any user here may read any process's arguments.
latest_secret() {
  local code
  code="$(jq -r '"header = \"Authorization: Bearer \(.access_token)\""' "$2" |
    get "${SECRETS_API}/$1/versions/latest:access" "$3" -K -)" || code=000
  rm -f "$2"
  printf '%s\n' "$code"
}

# ping_url_read: the ping URL into ping_url, or false, saying nothing of it. Only
# a URL of Healthchecks.io's own shape: a wrong value goes nowhere, and can't add
# to the config it's written into below.
ping_url_read() {
  local code
  ping_url=""
  code="$(get "${MDS}/instance/service-accounts/default/token" "${work}/ping-token.json" -H 'Metadata-Flavor: Google')"
  if [[ "$code" != 200 ]]; then
    rm -f "${work}/ping-token.json"
    return 1
  fi
  code="$(latest_secret "$PING_SECRET" "${work}/ping-token.json" "${work}/ping.json")"
  if [[ "$code" != 200 ]]; then
    rm -f "${work}/ping.json"
    return 1
  fi
  ping_url="$(jq -r '.payload.data // empty' "${work}/ping.json" 2>/dev/null | base64 -d 2>/dev/null)" || ping_url=""
  rm -f "${work}/ping.json"
  [[ "$ping_url" =~ ^https://hc-ping\.com/[A-Za-z0-9_/-]+$ ]]
}

# Pings the check: the URL to curl on stdin, and curl's own words nowhere, in case
# any of them holds it. The caller says what came of it.
ping_send() {
  ping_url_read || { ping_url=""; return 1; }
  printf 'url = "%s"\n' "$ping_url" |
    curl -fs -o /dev/null --max-time 20 --retry 3 --retry-connrefused -K - 2>/dev/null
  local rc=$?
  ping_url=""
  return "$rc"
}

# Pings the check if the guard is in the kernel and sshd is active, and otherwise
# doesn't, so that the check goes overdue. Never fails, and changes nothing here:
# what it says is all it does, whatever comes of it.
ping_if_up() {
  if ! guard_loaded; then
    log "no ping of the Healthchecks.io check: no metadata guard"
  elif ! guard_refuses_users; then
    log "no ping of the Healthchecks.io check: a user reaches the metadata server"
  elif ! systemctl is-active --quiet ssh.service; then
    log "no ping of the Healthchecks.io check: sshd isn't active"
  elif ping_send; then
    log "pinged the Healthchecks.io check"
  else
    warn "could not ping the Healthchecks.io check"
  fi
  return 0
}

# The daily ping: this file on disk, and a timer for it, an hour after the 04:00
# reboot. A subshell, as put dies on a failure: a failure here costs the daily
# ping alone. The check's timeout and grace are in scripts/healthchecks.sh.
ping_setup() {
  (
    put "${BASH_SOURCE[0]}" "$STARTUP_TOOL" 0755 root || true
    cat >"${work}/watchtower-ping.service" <<UNIT || exit 1
# config/bastion/startup.sh: only with the guard loaded and sshd active.
[Unit]
Description=Ping the bastion's Healthchecks.io check, if its guard and sshd are up
After=network-online.target nftables.service ssh.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${STARTUP_TOOL} ping
TimeoutStartSec=5min
UNIT
    cat >"${work}/watchtower-ping.timer" <<'UNIT' || exit 1
# config/bastion/startup.sh: the VM reboots only when an update needs it, so this
# is what keeps its check from going overdue while all is well.
[Unit]
Description=Ping the bastion's Healthchecks.io check every day

[Timer]
OnCalendar=*-*-* 05:00:00 UTC
AccuracySec=1min

[Install]
WantedBy=timers.target
UNIT
    put "${work}/watchtower-ping.service" /etc/systemd/system/watchtower-ping.service 0644 root || true
    put "${work}/watchtower-ping.timer" /etc/systemd/system/watchtower-ping.timer 0644 root || true
    systemctl daemon-reload || exit 1
    systemctl enable --now --quiet watchtower-ping.timer || exit 1
  ) || warn "could not set up the daily ping"
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
  code="$(latest_secret "$PEER_SECRET" "${work}/token.json" "${work}/peer.json")"
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
  # The temp file too: a reset in the middle of put leaves the key in it.
  rm -f "$WG_CONF" "${WG_CONF}.tmp" "$ALLOY_CONFIG"
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

  # The daily timer's way in.
  if [[ "${1:-}" == ping ]]; then
    ping_if_up
    return 0
  fi

  userns_off
  guard
  report_tool
  report_userns
  if guard_loaded; then
    log "metadata guard loaded"
  else
    warn "no metadata guard: this VM has no account, so no token to guard"
  fi

  updates
  installed wireguard-tools jq || apt_install --no-install-recommends wireguard-tools jq
  report_settled
  ping_setup
  ping_if_up
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
  mds_file instance/attributes/watchtower-alloy "${work}/bastion.alloy"
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
