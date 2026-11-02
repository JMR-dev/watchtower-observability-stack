#!/bin/bash
# The dead man's switch on the bastion's metadata guard. A ruleset that locks
# everyone out of the break-glass path must undo itself. config/bastion/
# startup.sh installs this as /usr/local/sbin/watchtower-ruleset, from the
# VM's metadata (watchtower-ruleset), and calls `setup` and `apply` at every
# boot; the units below call the rest. Root only.
#
#   setup            Writes the units and drop-ins below.
#   apply [<file> [<retry>]]
#                    Called with the ruleset in metadata, or with nothing when
#                    metadata didn't answer. Ends by starting sshd, or by
#                    stopping it when it may not run (gate). Exits 75 when it
#                    rolled back and is rebooting.
#   gate             May sshd run? Yes with the guard in the kernel, or on a VM
#                    with no account, so no token to guard. ssh.service runs
#                    it before every start.
#   confirm          Cancels the rollback. What a login triggers.
#   rollback         What the timer fires: the old ruleset back, the new one
#                    rejected, a reboot.
#
# apply, on a ruleset that differs from /etc/nftables.conf:
#
#   1. Keeps the old file, unless a trial is already running: an unconfirmed
#      ruleset is nobody's way back.
#   2. Records it as pending, on disk, and arms the 10-minute timer. The timer
#      is enabled and conditional on the record, so a reboot while pending
#      re-arms it even if the startup script never gets this far.
#   3. Installs it and loads it. One that won't load, or that has no guard
#      after all, rolls back at once.
#
# Confirming takes a login and no privileges: anyone may put a file in
# /run/watchtower-ruleset, sticky and world-writable, and the path unit runs
# `confirm` as root. It never reads what the file holds and its only effect is
# to cancel. A user can't reach `rollback` or a reboot through it, and flooding
# the directory confirms at the first file.
#
# The first install has no old ruleset. The VM has no account yet, so no token
# to guard: rollback puts back what was there, the package's empty ruleset, and
# sshd still runs, since gate lets it on a VM with no account. Step 7 then
# stops, with the VM running as no one.
#
# Each outcome prints one line, which reaches the serial console, and at every
# boot again, for scripts/bootstrap.sh:
#
#   bastion: ruleset pending|confirmed|rolled back|refused <sha256> at <epoch>
#
# scripts/check-bastion.sh tests all of it with systemctl stubbed.

set -euo pipefail

STATE="/var/lib/watchtower-bastion"
RULESET="/etc/nftables.conf"
OLD="${STATE}/nftables.old"
PENDING="${STATE}/pending"
CONFIRMED="${STATE}/confirmed"
REJECTED="${STATE}/rejected"
RETRY_SEEN="${STATE}/retry-seen"
DROPBOX="/run/watchtower-ruleset"
TOOL="/usr/local/sbin/watchtower-ruleset"
TIMER="watchtower-ruleset-rollback.timer"
ACCOUNT_URL="http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email"
# apply's exit status when it rolled back and is rebooting.
REBOOTING=75

say() { printf 'bastion: %s\n' "$*"; }
warn() { printf 'bastion: warning: %s\n' "$*" >&2; }

# The line scripts/bootstrap.sh reads. The time tells it from a line an earlier
# boot left in the serial output.
status() { say "ruleset $1 $2 at $(date +%s)"; }

guard_loaded() { nft list chain inet metadata_guard metadata >/dev/null 2>&1; }

# Only a 404 says so: anything else, the network not up yet included, may be a
# VM with a token. startup.sh runs gate again once the network is up.
no_account() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --retry 2 --retry-connrefused \
    -H 'Metadata-Flavor: Google' "$ACCOUNT_URL" || true)"
  [[ "$code" == 404 ]]
}

gate() {
  guard_loaded && return 0
  if no_account; then
    warn "no metadata guard, on a VM with no account and so no token: sshd may run"
    return 0
  fi
  say "error: no metadata guard on a VM with an account: sshd stays down"
  return 1
}

sha_of() { sha256sum "$1" | cut -d' ' -f1; }

read_state() { if [[ -f "$1" ]]; then cat "$1"; fi; }

# write_state <file> <value>: whole or not at all, even if the power goes.
write_state() {
  printf '%s\n' "$2" >"${1}.tmp"
  mv -f "${1}.tmp" "$1"
}

# install_ruleset <file>: the same way, as root's and world-readable, as the
# package's is.
install_ruleset() {
  install -m 0644 -o root -g root "$1" "${RULESET}.tmp"
  mv -f "${RULESET}.tmp" "$RULESET"
}

# Everything that changes the state holds this. Non-root can't open it.
lock() {
  install -d -m 0700 "$STATE" "$REJECTED"
  exec 9>"${STATE}/lock"
  flock 9
}

load_ruleset() { systemctl reload-or-restart nftables.service && guard_loaded; }

# With the lock held and a ruleset pending.
roll_back() {
  local sha
  sha="$(read_state "$PENDING")"
  : >"${REJECTED}/${sha}"
  if [[ -f "$OLD" ]]; then
    install_ruleset "$OLD"
  else
    rm -f "$RULESET"
  fi
  rm -f "$PENDING"
  sync
  status "rolled back" "$sha"
  # The reboot loads what's on disk, and clears whatever the rejected one did.
  systemctl --no-block reboot
}

# The ruleset on disk, as it is, into the kernel, when the boot didn't get it
# there: else the old one, into the kernel alone, so the next boot tries the
# current one again. True when the guard is on.
load_current() {
  systemctl reload-or-restart nftables.service || warn "nftables.service did not load ${RULESET}"
  guard_loaded && return 0
  if [[ -f "$OLD" ]] && nft --file "$OLD" && guard_loaded; then
    warn "${RULESET} did not load: running on the old ruleset"
    return 0
  fi
  return 1
}

# abandon <why> <the trial already running, if any>: with the lock held. A trial
# that can't start leaves things as they were. One already running ends, as a
# rollback: clearing its record would leave an unconfirmed ruleset on disk with
# no timer, and the next boot would take it for a confirmed one.
abandon() {
  if [[ -n "$2" ]]; then
    warn "$1: the trial can't go on, so rolling back now"
    write_state "$PENDING" "$2"
    roll_back
    return "$REBOOTING"
  fi
  warn "$1: the ruleset on disk stays"
  rm -f "$PENDING"
  systemctl stop "$TIMER" || true
  return 1
}

# try <file> <sha>: starts a trial, or picks one up again after a reboot.
try() {
  local new=$1 sha=$2 running
  running="$(read_state "$PENDING")"
  if [[ -z "$running" ]]; then
    if [[ -f "$RULESET" ]]; then
      { cp -f "$RULESET" "${OLD}.tmp" && mv -f "${OLD}.tmp" "$OLD"; } || abandon "could not keep the old ruleset" "" || return
    else
      rm -f "$OLD"
    fi
  fi
  write_state "$PENDING" "$sha" || abandon "could not record the trial" "$running" || return
  sync
  # Armed before it's loaded, so nothing it does can stop the rollback. No
  # timer, no trial.
  systemctl restart "$TIMER" || abandon "could not arm the timer" "$running" || return
  if ! { [[ -f "$RULESET" ]] && cmp -s "$new" "$RULESET"; }; then
    install_ruleset "$new" || abandon "could not install the new ruleset" "$running" || return
  fi
  sync
  if ! load_ruleset; then
    warn "the new ruleset did not load or has no guard: rolling back now"
    roll_back
    return "$REBOOTING"
  fi
  status pending "$sha"
}

# apply_new <file>: what the ruleset in metadata means for this boot.
apply_new() {
  local new=$1 retry=${2:-} sha pending current="" confirmed
  sha="$(sha_of "$new")"
  pending="$(read_state "$PENDING")"
  confirmed="$(read_state "$CONFIRMED")"
  [[ ! -f "$RULESET" ]] || current="$(sha_of "$RULESET")"

  # scripts/bootstrap.sh asks for a rejected file again with a new value here,
  # once: the same value again can't make a rollback loop.
  if [[ -n "$retry" && "$retry" != "$(read_state "$RETRY_SEEN")" ]]; then
    write_state "$RETRY_SEEN" "$retry"
    rm -f "${REJECTED}/${sha}"
  fi

  if [[ -e "${REJECTED}/${sha}" ]]; then
    status "rolled back" "$sha"
  elif ! nft --check --file "$new" || ! grep -q 'table inet metadata_guard' "$new" || ! grep -q 'chain metadata' "$new"; then
    # Never installed, so nothing to roll back. What runs now stays.
    warn "the ruleset in metadata fails nft --check or has no guard"
    status refused "$sha"
  elif [[ "$sha" == "$pending" ]]; then
    try "$new" "$sha" || return
  elif [[ -z "$pending" && "$sha" == "$current" ]]; then
    # No change. A file with no record has been running through a boot, which
    # nothing but a lost state directory leaves.
    write_state "$CONFIRMED" "$sha"
    status confirmed "$sha"
  elif [[ -n "$pending" && "$sha" == "$confirmed" ]]; then
    # Back to what was confirmed, in the middle of a trial.
    install_ruleset "$new"
    rm -f "$PENDING"
    sync
    systemctl stop "$TIMER" || true
    load_ruleset || warn "the confirmed ruleset did not load"
    status confirmed "$sha"
  else
    try "$new" "$sha" || return
  fi
}

cmd_apply() {
  local new=${1:-} retry=${2:-} rc=0 pending
  lock
  # The power went in the middle of a rollback.
  pending="$(read_state "$PENDING")"
  if [[ -n "$pending" && -e "${REJECTED}/${pending}" ]]; then
    roll_back
    exit "$REBOOTING"
  fi
  if [[ -n "$new" ]]; then
    apply_new "$new" "$retry" || rc=$?
    [[ "$rc" -ne "$REBOOTING" ]] || exit "$REBOOTING"
    [[ "$rc" -eq 0 ]] || warn "the ruleset could not be applied"
  fi
  guard_loaded || load_current || true
  if gate; then
    systemctl reset-failed ssh.service 2>/dev/null || true
    systemctl start ssh.service
  else
    systemctl stop ssh.service || true
    say "error: sshd stays down: the way back is the serial console or new metadata (docs/runbook.md)"
    exit 1
  fi
}

cmd_confirm() {
  local pending
  lock
  # By name, never following anything a user left here.
  find "$DROPBOX" -mindepth 1 -delete 2>/dev/null || true
  pending="$(read_state "$PENDING")"
  [[ -n "$pending" ]] || return 0
  write_state "$CONFIRMED" "$pending"
  rm -f "$PENDING"
  sync
  systemctl stop "$TIMER" || true
  status confirmed "$pending"
}

cmd_rollback() {
  lock
  [[ -n "$(read_state "$PENDING")" ]] || return 0
  roll_back
}

# put <path> on stdin: the file, 0644 and root's.
put() {
  install -d -m 0755 "$(dirname "$1")"
  cat >"${1}.tmp"
  chmod 0644 "${1}.tmp"
  mv -f "${1}.tmp" "$1"
}

cmd_setup() {
  # Decision 8: Debian's unit flushes the whole ruleset on a stop, so a
  # package upgrade's restart would open the guard for as long as the start
  # takes, or for good if the start failed. Without it a restart only loads
  # the file, which replaces the guard's table in one transaction.
  put /etc/systemd/system/nftables.service.d/watchtower.conf <<'UNIT'
# config/bastion/ruleset.sh: a restart reloads, and never flushes the guard.
[Service]
ExecStop=
UNIT

  # Not Requires=: a restart of nftables.service would restart sshd with it,
  # and one that failed (a bad file, in a package upgrade) would leave sshd
  # down with the guard still loaded. gate asks the kernel instead, at every
  # start, so an upgrade of either package leaves both running. Wants= and
  # After= only put the guard first at boot.
  put /etc/systemd/system/ssh.service.d/watchtower-guard.conf <<UNIT
# config/bastion/ruleset.sh: no sshd without the metadata guard.
[Unit]
Wants=nftables.service
After=nftables.service

[Service]
ExecStartPre=${TOOL} gate
UNIT

  put /etc/systemd/system/watchtower-ruleset-rollback.timer <<UNIT
# config/bastion/ruleset.sh: armed by a pending ruleset, at every boot too.
[Unit]
Description=Roll the metadata guard's ruleset back unless a login confirms it
ConditionPathExists=${PENDING}

[Timer]
OnActiveSec=10min
AccuracySec=1s

[Install]
WantedBy=timers.target
UNIT

  put /etc/systemd/system/watchtower-ruleset-rollback.service <<UNIT
# config/bastion/ruleset.sh
[Unit]
Description=Put the metadata guard's old ruleset back and reboot

[Service]
Type=oneshot
ExecStart=${TOOL} rollback
StandardOutput=journal+console
StandardError=journal+console
UNIT

  put /etc/systemd/system/watchtower-ruleset-confirm.path <<UNIT
# config/bastion/ruleset.sh: any user may ask, so no limit may stop the asking.
[Unit]
Description=Watch for a login confirming the metadata guard's ruleset

[Path]
DirectoryNotEmpty=${DROPBOX}
MakeDirectory=yes
DirectoryMode=1777
TriggerLimitIntervalSec=0

[Install]
WantedBy=paths.target
UNIT

  put /etc/systemd/system/watchtower-ruleset-confirm.service <<UNIT
# config/bastion/ruleset.sh
[Unit]
Description=Cancel the metadata guard's rollback
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=${TOOL} confirm
StandardOutput=journal+console
StandardError=journal+console
UNIT

  # Being logged in is all it takes, in an interactive shell. A command over
  # SSH doesn't read this, so CI asks by hand (scripts/bastion-confirm.sh).
  put /etc/profile.d/watchtower-ruleset.sh <<SH
# config/bastion/ruleset.sh: a login shows the bastion is reachable.
[ ! -d ${DROPBOX} ] || touch "${DROPBOX}/login-\$\$" 2>/dev/null || true
SH

  systemctl daemon-reload
  systemctl enable --quiet nftables.service "$TIMER" watchtower-ruleset-confirm.path
  systemctl start watchtower-ruleset-confirm.path
}

main() {
  local cmd=${1:-}
  shift || true
  [[ "$(id -u)" == 0 ]] || { echo "watchtower-ruleset: root only" >&2; exit 1; }
  case "$cmd" in
    setup) cmd_setup ;;
    apply) cmd_apply "$@" ;;
    gate) gate ;;
    confirm) cmd_confirm ;;
    rollback) cmd_rollback ;;
    *) echo "usage: watchtower-ruleset setup|apply|gate|confirm|rollback" >&2; exit 2 ;;
  esac
}

main "$@"
