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
#                    rejected, a reboot. Retried until the disk takes it.
#   floor            Loads the guard at its smallest, from this file: what's
#                    left when no ruleset on disk will do.
#
# apply, on a ruleset that differs from /etc/nftables.conf:
#
#   1. Loads it in a network namespace of its own, where nothing can see it, and
#      refuses it unless that gives a hooked guard.
#   2. Keeps the old file, unless a trial is already running (an unconfirmed
#      ruleset is nobody's way back) or the old file no longer loads.
#   3. Records it as pending, on disk, and arms the 10-minute timer. The timer
#      is enabled and conditional on the record, so a reboot while pending
#      re-arms it even if the startup script never gets this far.
#   4. Installs it and loads it. One that won't load, or that has no guard
#      after all, rolls back at once.
#
# A rollback loads the old ruleset into the kernel first, which takes no disk,
# then puts it back on disk. Only then does it clear the record and reboot: a
# restore that fails (a full or read-only disk) stays on the record and is
# retried, and can't become a reboot loop.
#
# Confirming takes a login and no privileges: anyone may put a file in
# /run/watchtower-ruleset, a tiny tmpfs, sticky and world-writable, and the path
# unit runs `confirm` as root. It never reads what the file holds and its only
# effect is to cancel. A user can't reach `rollback` or a reboot through it, and
# flooding the directory confirms at the first file. A trial empties the
# directory once it's loaded, so a login from before the load confirms nothing.
# And nothing of a user's runs without a login (setup), so nothing confirms
# without one.
#
# The first install has no old ruleset. The VM has no account yet, so no token
# to guard: rollback puts back what was there, the package's empty ruleset, and
# sshd still runs, on the floor. Step 7 then stops, with the VM running as no
# one.
#
# Each outcome, at every boot again, is a line on the serial console for whoever
# reads it, and the guest attribute watchtower/ruleset for scripts/bootstrap.sh:
#
#   pending|confirmed|rolled back|refused|failed <sha256> at <epoch>
#
# failed: it should be on and isn't, or a rollback's restore hasn't worked yet.
# bootstrap can't go by the console, as any user can put a line there (logger,
# through rsyslog). The guard keeps them from the attribute.
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
# On /run, so a read-only disk can't keep a rollback from loading the old
# ruleset.
LOCK="/run/watchtower-ruleset.lock"
DROPBOX="/run/watchtower-ruleset"
# systemd's own name for a mount there.
DROPBOX_MOUNT='run-watchtower\x2druleset.mount'
TOOL="/usr/local/sbin/watchtower-ruleset"
TIMER="watchtower-ruleset-rollback.timer"
ROLLBACK="watchtower-ruleset-rollback.service"
ACCOUNT_URL="http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email"
ATTRIBUTE_URL="http://169.254.169.254/computeMetadata/v1/instance/guest-attributes/watchtower/ruleset"
# apply's exit status when it rolled back and is rebooting.
REBOOTING=75

say() { printf 'bastion: %s\n' "$*"; }
warn() { printf 'bastion: warning: %s\n' "$*" >&2; }

# status <state> <sha>: what came of it. The time tells scripts/bootstrap.sh this
# boot's from an earlier one's, which the attribute outlasts. Telling it never
# changes what came of it.
status() {
  local value
  value="$1 $2 at $(date +%s)"
  say "ruleset ${value}"
  curl -fsS -o /dev/null --max-time 5 --retry 2 --retry-connrefused -X PUT -H 'Metadata-Flavor: Google' \
    --data "$value" "$ATTRIBUTE_URL" || warn "could not put that in the guest attribute"
}

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

# Everything below that changes the state or the disk is called under `||` or
# `if`, where set -e is off, so each step says when it failed and the next
# doesn't run.

# write_state <file> <value>: whole or not at all, even if the power goes.
write_state() {
  if ! { printf '%s\n' "$2" >"${1}.tmp" && mv -f "${1}.tmp" "$1"; }; then
    rm -f "${1}.tmp"
    return 1
  fi
}

# install_ruleset <file>: the same way, as root's and world-readable, as the
# package's is.
install_ruleset() {
  if ! { install -m 0644 -o root -g root "$1" "${RULESET}.tmp" && mv -f "${RULESET}.tmp" "$RULESET"; }; then
    rm -f "${RULESET}.tmp"
    return 1
  fi
}

# Everything that changes the state holds this. Non-root can't open it, so
# can't hold it either.
lock() {
  [[ -d "$REJECTED" ]] || install -d -m 0700 "$STATE" "$REJECTED"
  (umask 077 && : >>"$LOCK")
  exec 9>"$LOCK"
  flock 9
}

load_ruleset() { systemctl reload-or-restart nftables.service && guard_loaded; }

# The kernel's own answer, without touching what runs: a network namespace of
# its own has its own rules, and is gone when nft exits.

# loads <file>: this file loads.
loads() { unshare --net nft --file "$1"; }

# guards <file>: this file loads, and gives a guard that is hooked, whatever its
# comments say.
guards() {
  local listed
  # shellcheck disable=SC2016 # for the inner shell
  listed="$(unshare --net bash -c 'nft --file "$1" && nft list table inet metadata_guard' bash "$1")" || return 1
  [[ "$listed" == *"hook output"* &&
    "$listed" == *"ip daddr 169.254.169.254 jump metadata"* &&
    "$listed" == *"ip6 daddr fd20:ce::254 jump metadata"* &&
    "$listed" == *"meta skuid != 0"* ]]
}

# The guard at its smallest (config/bastion/nftables.conf's rules, and
# scripts/check-bastion.sh keeps them equal), for when no file will do. It can't
# lock anyone out, since it only ever touches the way to the metadata server,
# and it needs nothing on disk.
floor() {
  nft --file - <<'NFT'
flush ruleset

table inet metadata_guard {
	chain output {
		type filter hook output priority filter; policy accept;
		ip daddr 169.254.169.254 jump metadata
		ip6 daddr fd20:ce::254 jump metadata
	}

	chain metadata {
		udp dport { 53, 67, 123 } accept
		tcp dport 53 accept
		meta skuid != 0 counter reject with icmpx admin-prohibited
	}
}
NFT
}

# The old ruleset into the kernel alone, if it has a guard, else the floor. Takes
# no disk. True when the guard is on.
old_into_kernel() {
  if [[ -f "$OLD" ]] && guards "$OLD" && nft --file "$OLD" && guard_loaded; then
    return 0
  fi
  warn "no old ruleset with a guard: loading the floor"
  floor && guard_loaded
}

# restore_old <sha>: the disk, the rejection first, the record last, so a power
# cut anywhere in it leaves a rollback that the next boot finishes.
restore_old() {
  : >"${REJECTED}/${1}" || return 1
  if [[ -f "$OLD" ]]; then
    install_ruleset "$OLD" || return 1
  else
    rm -f "$RULESET" || return 1
  fi
  rm -f "$PENDING" || return 1
  sync
}

# With the lock held and a ruleset pending. False when the disk wouldn't take the
# old ruleset: the record stays, and what's in the kernel is the way in meanwhile.
roll_back() {
  local sha
  sha="$(read_state "$PENDING")"
  old_into_kernel || warn "neither the old ruleset nor the floor would load"
  if ! restore_old "$sha"; then
    warn "could not put the old ruleset back on disk: it runs from the kernel, and this retries (docs/runbook.md)"
    status failed "$sha"
    return 1
  fi
  status "rolled back" "$sha"
  # The reboot loads what's on disk, and clears whatever the rejected one did.
  systemctl --no-block reboot
}

# With the lock held and a ruleset pending. Returns $REBOOTING when it rolled
# back, else 1, with the timer's service left to keep trying: it waits for this
# lock, fails, and comes back by its Restart=.
end_trial() {
  if roll_back; then
    return "$REBOOTING"
  fi
  systemctl --no-block start "$ROLLBACK" || warn "could not start ${ROLLBACK}"
  return 1
}

# abandon <why> <the trial already running, if any>: with the lock held. A trial
# that can't start leaves things as they were. One already running ends, as a
# rollback: clearing its record would leave an unconfirmed ruleset on disk with
# no timer, and the next boot would take it for a confirmed one.
abandon() {
  if [[ -n "$2" ]]; then
    warn "$1: the trial can't go on, so rolling back now"
    write_state "$PENDING" "$2" || warn "could not record which trial that is"
    end_trial
    return
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
  if [[ -z "$running" && -f "$RULESET" ]] && ! cmp -s "$new" "$RULESET"; then
    # What has stopped loading is no way back: the last one that loaded stays.
    if loads "$RULESET"; then
      { cp -f "$RULESET" "${OLD}.tmp" && mv -f "${OLD}.tmp" "$OLD"; } || abandon "could not keep the old ruleset" "" || return
    else
      warn "${RULESET} no longer loads, so ${OLD} stays the way back"
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
    end_trial
    return
  fi
  # sshd was already up on the old ruleset: a login from then shows nothing about
  # this one, and may be queued behind this lock.
  find "$DROPBOX" -mindepth 1 -delete 2>/dev/null || true
  status pending "$sha"
}

# apply_new <file>: what the ruleset in metadata means for this boot.
apply_new() {
  local new=$1 retry=${2:-} sha pending current="" confirmed retried=""
  sha="$(sha_of "$new")"
  pending="$(read_state "$PENDING")"
  confirmed="$(read_state "$CONFIRMED")"
  [[ ! -f "$RULESET" ]] || current="$(sha_of "$RULESET")"

  # scripts/bootstrap.sh asks for a rejected file again with a new value here,
  # once: the same value again can't make a rollback loop.
  if [[ -n "$retry" && "$retry" != "$(read_state "$RETRY_SEEN")" ]]; then
    if write_state "$RETRY_SEEN" "$retry"; then
      [[ ! -e "${REJECTED}/${sha}" ]] || retried=1
      rm -f "${REJECTED}/${sha}"
    else
      warn "could not record the retry, so it waits for a boot that can"
    fi
  fi

  if [[ -e "${REJECTED}/${sha}" ]]; then
    status "rolled back" "$sha"
  elif ! guards "$new"; then
    # Never installed, so nothing to roll back. What runs now stays.
    warn "the ruleset in metadata doesn't load or gives no guard"
    status refused "$sha"
  elif [[ "$sha" == "$pending" ]]; then
    try "$new" "$sha" || return
  elif [[ -z "$pending" && "$sha" == "$current" && -z "$retried" ]]; then
    # No change. A file with no record has been running through a boot, which
    # nothing but a lost state directory leaves. Confirmed only if it's what
    # the guard came from: the kernel may hold the old one or the floor.
    if load_ruleset; then
      write_state "$CONFIRMED" "$sha" || warn "could not record it as confirmed"
      status confirmed "$sha"
    else
      warn "${RULESET} did not load, or has no guard"
      status failed "$sha"
    fi
  elif [[ -n "$pending" && "$sha" == "$confirmed" ]]; then
    # Back to what was confirmed, in the middle of a trial. The trial and its
    # timer stand until that's on disk.
    if ! install_ruleset "$new" || ! rm -f "$PENDING"; then
      warn "could not put the confirmed ruleset back, so the trial stands"
      status failed "$sha"
      return 1
    fi
    sync
    systemctl stop "$TIMER" || true
    if load_ruleset; then
      status confirmed "$sha"
    else
      warn "the confirmed ruleset did not load"
      status failed "$sha"
    fi
  else
    try "$new" "$sha" || return
  fi
}

cmd_apply() {
  local new=${1:-} retry=${2:-} rc=0 pending
  lock
  pending="$(read_state "$PENDING")"
  if [[ -n "$pending" && -e "${REJECTED}/${pending}" ]]; then
    # A rollback the power cut short or the disk refused. It finishes before
    # anything new goes on.
    end_trial || rc=$?
  elif [[ -n "$new" ]]; then
    apply_new "$new" "$retry" || rc=$?
  fi
  [[ "$rc" -ne "$REBOOTING" ]] || exit "$REBOOTING"
  [[ "$rc" -eq 0 ]] || warn "the ruleset could not be applied"
  guard_loaded || load_ruleset || old_into_kernel || warn "nothing would load, not even the floor"
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
  # A file from before the load went with the load (try).
  [[ -n "$(find "$DROPBOX" -mindepth 1 -print -quit 2>/dev/null)" ]] || return 0
  # By name, never following anything a user left here.
  find "$DROPBOX" -mindepth 1 -delete 2>/dev/null || true
  pending="$(read_state "$PENDING")"
  [[ -n "$pending" ]] || return 0
  # Rejected already, with its rollback still trying to reach the disk.
  [[ ! -e "${REJECTED}/${pending}" ]] || return 0
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

# put <path> on stdin: the file, 0644 and root's. A directory that's there keeps
# its own mode: polkit's is its own.
put() {
  [[ -d "$(dirname "$1")" ]] || install -d -m 0755 "$(dirname "$1")"
  cat >"${1}.tmp"
  chmod 0644 "${1}.tmp"
  mv -f "${1}.tmp" "$1"
}

cmd_setup() {
  # Decision 8: Debian's unit flushes the whole ruleset on a stop, so a
  # package upgrade's restart would open the guard for as long as the start
  # takes, or for good if the start failed. Without it a restart only loads
  # the file, which replaces the guard's table in one transaction. A file that
  # won't load, at a boot, leaves the kernel with no rules: the floor goes on
  # before the network comes up, so that's never the metadata server open.
  put /etc/systemd/system/nftables.service.d/watchtower.conf <<'UNIT'
# config/bastion/ruleset.sh: a restart reloads, and never flushes the guard.
[Unit]
OnFailure=watchtower-ruleset-floor.service

[Service]
ExecStop=
UNIT

  put /etc/systemd/system/watchtower-ruleset-floor.service <<UNIT
# config/bastion/ruleset.sh: as early as nftables.service, which this follows.
[Unit]
Description=Load the metadata guard's floor, as its ruleset did not load
DefaultDependencies=no
Before=network-pre.target

[Service]
Type=oneshot
ExecStart=${TOOL} floor
StandardOutput=journal+console
StandardError=journal+console
UNIT

  # What a user leaves behind runs at a boot with no sshd and no gate: on a VM
  # with no guard it would reach the token, and on any VM it would confirm a
  # trial with no one logged in. So nothing of a user's runs without a login: no
  # crontab, no at job and no lingering, and any left from before go.
  printf 'root\n' | put /etc/cron.allow
  printf 'root\n' | put /etc/at.allow
  find /var/spool/cron/crontabs -mindepth 1 ! -name root -delete 2>/dev/null || true
  rm -f /var/lib/systemd/linger/*
  put /etc/polkit-1/rules.d/10-watchtower-ruleset.rules <<'RULES'
// config/bastion/ruleset.sh: no user's units run without a login. Root isn't asked.
polkit.addRule(function (action, subject) {
  if (action.id == "org.freedesktop.login1.set-self-linger" ||
      action.id == "org.freedesktop.login1.set-user-linger") {
    return polkit.Result.NO;
  }
});
RULES

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
# config/bastion/ruleset.sh: fails only when the disk won't take the old ruleset,
# with the old one already in the kernel, so it may retry for as long as that lasts.
[Unit]
Description=Put the metadata guard's old ruleset back and reboot
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=${TOOL} rollback
Restart=on-failure
RestartSec=60
StandardOutput=journal+console
StandardError=journal+console
UNIT

  # On a tmpfs of its own and a very small one: open to every user, it would
  # otherwise be room for them to fill /run, which refuses systemd a reload when
  # full. An empty file takes none of its pages, so filling it stops no one asking.
  put "/etc/systemd/system/${DROPBOX_MOUNT}" <<UNIT
# config/bastion/ruleset.sh: sticky, open to all, and room for nothing but names.
[Unit]
Description=The directory a login confirms the metadata guard's ruleset in

[Mount]
What=tmpfs
Where=${DROPBOX}
Type=tmpfs
Options=mode=1777,size=64k,nr_inodes=1024,nosuid,nodev,noexec
UNIT

  put /etc/systemd/system/watchtower-ruleset-confirm.path <<UNIT
# config/bastion/ruleset.sh: any user may ask, so no limit may stop the asking.
[Unit]
Description=Watch for a login confirming the metadata guard's ruleset
RequiresMountsFor=${DROPBOX}

[Path]
DirectoryNotEmpty=${DROPBOX}
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
    floor) floor ;;
    *) echo "usage: watchtower-ruleset setup|apply|gate|confirm|rollback|floor" >&2; exit 2 ;;
  esac
}

main "$@"
