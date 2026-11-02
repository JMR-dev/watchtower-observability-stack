#!/bin/bash
# A one-off startup script for the break-glass bastion, for when SSH is gone. It
# needs no SSH and no local password, which the bastion doesn't have: GCE runs it
# as root at the next boot. docs/runbook.md, "The bastion with SSH gone", has the
# commands that put it in metadata in place of startup.sh, and that put startup.sh
# back. Not one of the files scripts/bootstrap.sh puts there.
#
# Every line it says starts "bastion-recovery:", and goes to the serial console,
# which can be read without logging in. It carries on whatever a step does, and
# always exits 0.
#
#   1. Says how full the disk is, and remounts a read-only root read-write.
#   2. Only with / over FULL_PERCENT used, in blocks or inodes: empties apt's cache,
#      old rotated logs and the journal past 64M. Still that full, Alloy's buffer
#      goes too (what it hadn't shipped yet is lost), and it names the largest
#      paths. It never removes a user's files: that's a line for you to add to a
#      copy of this script, once you've read which ones they are.
#   3. Checks the ruleset's tool, which sshd's gate depends on. Missing or cut short,
#      it's restored from metadata (watchtower-ruleset), whole or not at all.
#   4. Asks that tool to end with sshd up: `watchtower-ruleset apply`, with no new
#      ruleset. A rollback the full disk held up finishes here and reboots, and this
#      script then runs once more. sshd stays subject to the gate: no guard on a VM
#      with an account, no sshd. And with no tool at all, no sshd: this never starts
#      sshd some other way.
#   5. If sshd still isn't up, reinstalls nftables and asks again, then shows why.
#   6. Says where the guard and sshd ended up, and "done".
#
# With nothing wrong it changes nothing but starting what should be running, so
# it's safe to try on a healthy bastion. scripts/check-bastion.sh tests it.

set -u
export DEBIAN_FRONTEND=noninteractive

RULESET_TOOL="/usr/local/sbin/watchtower-ruleset"
TOOL_IN_METADATA="http://169.254.169.254/computeMetadata/v1/instance/attributes/watchtower-ruleset"
ALLOY_DATA="/var/lib/alloy/data"
FULL_PERCENT=90
# ruleset.sh's exit status when it rolled back and is rebooting.
RULESET_REBOOTING=75

say() { printf 'bastion-recovery: %s\n' "$*"; }
# Whatever a command said, under this script's prefix.
quote() { sed 's/^/bastion-recovery:   /'; }

used() { df --output="$1" / | tail -n 1 | tr -dc '0-9'; }
is_full() { [[ "$(used pcent)" -ge "$FULL_PERCENT" || "$(used ipcent)" -ge "$FULL_PERCENT" ]]; }
say_disk() { say "disk: $(used pcent)% of / used, $(used ipcent)% of its inodes"; }

# By its rules where the tool can say, else by its name.
guard_loaded() {
  if tool_whole "$RULESET_TOOL"; then
    "$RULESET_TOOL" loaded >/dev/null 2>&1
  else
    nft list chain inet metadata_guard metadata >/dev/null 2>&1
  fi
}
sshd_active() { systemctl is-active --quiet ssh.service; }

writable_root() {
  if findmnt -no OPTIONS / | grep -qE '(^|,)ro(,|$)'; then
    say "/ is read-only: remounting it read-write (a filesystem error may refuse this)"
    mount -o remount,rw / 2>&1 | quote
  fi
}

free_disk() {
  is_full || { say "not full: removing nothing"; return 0; }
  say "over ${FULL_PERCENT}%: emptying apt's cache, old rotated logs and the journal past 64M"
  apt-get clean 2>&1 | quote
  find /var/log -xdev -type f \( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' \) -delete 2>&1 | quote
  journalctl --vacuum-size=64M 2>&1 | quote
  say_disk
  is_full || return 0
  say "still over ${FULL_PERCENT}%: removing Alloy's buffer, so what it hadn't shipped is lost"
  systemctl stop alloy.service 2>&1 | quote
  find "$ALLOY_DATA" -xdev -mindepth 1 -delete 2>&1 | quote
  systemctl start alloy.service 2>&1 | quote
  say_disk
  is_full || return 0
  say "still over ${FULL_PERCENT}%: the largest paths, for a line of your own in a copy of this script"
  du -xh --max-depth=2 / 2>/dev/null | sort -rh | head -n 12 | quote
}

# tool_whole <file>: there, executable, parses, and ends as the tool ends: a file cut
# at a line can parse and do nothing, which sshd's gate would take for a yes.
tool_whole() {
  # shellcheck disable=SC2016 # the tool's own last line, as written
  [[ -x "$1" ]] && bash -n "$1" 2>/dev/null && [[ "$(tail -n 1 "$1")" == 'main "$@"' ]]
}

# Whole or not at all: a temp file beside it, checked, then moved over it.
restore_tool() {
  local tmp="${RULESET_TOOL}.tmp"
  tool_whole "$RULESET_TOOL" && return 0
  say "${RULESET_TOOL} is missing or cut short: restoring it from metadata"
  # A file by name, which curl starts over on a retry: on stdout, a first try that
  # stalled would leave its part in front of the whole.
  curl -fsS --retry 5 --retry-connrefused --max-time 30 -H 'Metadata-Flavor: Google' \
    -o "$tmp" "$TOOL_IN_METADATA" 2>/dev/null || say "metadata has no watchtower-ruleset to give, or didn't answer"
  chmod 0755 "$tmp" 2>/dev/null
  if tool_whole "$tmp" && mv -f "$tmp" "$RULESET_TOOL"; then
    say "restored it"
    return 0
  fi
  rm -f "$tmp"
  say "could not restore it: sshd's gate needs it, so sshd can't start without it"
  return 1
}

# Exits here when a rollback finished and the VM is rebooting.
ask_for_sshd() {
  local rc=0
  if ! tool_whole "$RULESET_TOOL"; then
    say "no usable ${RULESET_TOOL}: starting the guard, and asking sshd, whose gate will refuse without it"
    systemctl start nftables.service 2>&1 | quote
    systemctl reset-failed ssh.service 2>&1 | quote
    systemctl start ssh.service 2>&1 | quote
    return 0
  fi
  "$RULESET_TOOL" apply 2>&1 | quote
  rc=${PIPESTATUS[0]}
  if [[ "$rc" -eq "$RULESET_REBOOTING" ]]; then
    say "a rollback finished: rebooting, and this script runs once more"
    exit 0
  fi
}

reinstall_nftables() {
  say "sshd isn't up: reinstalling nftables and asking again"
  dpkg --force-confdef --force-confold --configure -a 2>&1 | quote
  apt-get -q -o DPkg::Lock::Timeout=120 update 2>&1 | quote
  apt-get -q -o DPkg::Lock::Timeout=120 install -y --reinstall --no-install-recommends nftables 2>&1 | quote
}

say_why() {
  say "why sshd isn't up:"
  sshd -t 2>&1 | quote
  journalctl -b -n 20 --no-pager -u nftables -u ssh 2>&1 | quote
}

main() {
  say "start: $(date -u '+%F %T UTC')"
  say_disk
  writable_root
  free_disk
  restore_tool
  ask_for_sshd
  if ! sshd_active; then
    reinstall_nftables
    ask_for_sshd
  fi
  sshd_active || say_why
  if guard_loaded; then say "guard: loaded"; else say "guard: NOT loaded"; fi
  if sshd_active; then say "sshd: active"; else say "sshd: NOT active"; fi
  say_disk
  say "done"
  exit 0
}

main "$@"
