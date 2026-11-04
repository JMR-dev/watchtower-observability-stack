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
#      it's restored from its last good copy, or else from metadata
#      (watchtower-ruleset) if that copy passes the same self-check startup.sh asks
#      of a new tool. Whole or not at all.
#   4. Asks that tool to end with sshd up: `watchtower-ruleset apply`, with no new
#      ruleset. A rollback the full disk held up finishes here and reboots, and this
#      script then runs once more. If the tool fails, its last good copy takes its
#      place and is asked the same. sshd stays subject to the gate: no guard on a VM
#      with an account, no sshd.
#   5. If sshd still isn't up, reinstalls nftables and asks again, then shows why.
#   6. Says where the guard and sshd ended up, and "done".
#
# Never sshd without the gate (the owner's decision, 2026-11-04): this script never
# starts sshd itself, only the tool does, through its gate. With no usable tool at all
# it doesn't ask for sshd, so it doesn't rely on sshd's drop-in being on disk to keep it
# down. The way back from there is a rerun of scripts/bootstrap.sh.
#
# With nothing wrong it changes nothing but starting what should be running, so
# it's safe to try on a healthy bastion. scripts/check-bastion.sh tests it.

set -u
export DEBIAN_FRONTEND=noninteractive

RULESET_TOOL="/usr/local/sbin/watchtower-ruleset"
# startup.sh keeps it: the last copy that passed its self-check and brought sshd up.
TOOL_LAST_GOOD="/usr/local/sbin/watchtower-ruleset.last-good"
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

# tool_in_namespace <tool> <floor file>: startup.sh's, word for word but for say, run
# by tool_self_check alone in a network namespace of its own. No rules is no guard, and
# no guard with the metadata server out of reach keeps sshd down; its own floor,
# loaded, guards; and with it on, sshd may run.
# shellcheck disable=SC2329 # run by tool_self_check, through declare -f
tool_in_namespace() {
  local tool=$1 floor=$2
  nft --check --file "$floor" || { say "its floor doesn't pass nft --check"; return 1; }
  if "$tool" loaded >/dev/null 2>&1; then say "it takes an empty ruleset for a guard"; return 1; fi
  if "$tool" gate >/dev/null 2>&1; then say "its gate lets sshd run with no guard"; return 1; fi
  "$tool" probe "$floor" >/dev/null 2>&1 || { say "its floor doesn't guard"; return 1; }
  "$tool" gate >/dev/null 2>&1 || { say "its gate keeps sshd down with its floor on"; return 1; }
}

# tool_self_check <tool>: startup.sh's, the same checks, in a network namespace that's
# gone when it ends, so nothing it loads reaches the live kernel.
tool_self_check() {
  local tool=$1 floor="${work}/floor.nft"
  tool_whole "$tool" || { say "${tool} is cut short or won't parse"; return 1; }
  "$tool" floor-rules >"$floor" 2>/dev/null || { say "${tool} won't render its floor"; return 1; }
  unshare --net bash -c "$(declare -f say tool_in_namespace); tool_in_namespace \"\$@\"" bash "$tool" "$floor"
}

# install_tool <file>: in the tool's place, whole or not at all: a temp file beside it,
# checked, then moved over it.
install_tool() {
  local tmp="${RULESET_TOOL}.tmp"
  if cp -f "$1" "$tmp" 2>/dev/null && chmod 0755 "$tmp" && tool_whole "$tmp" && mv -f "$tmp" "$RULESET_TOOL"; then
    return 0
  fi
  rm -f "$tmp"
  return 1
}

# The tool whole again: its last good copy first, which has brought sshd up before,
# then metadata's, only if it passes the self-check.
restore_tool() {
  local fetched="${work}/ruleset.sh"
  tool_whole "$RULESET_TOOL" && return 0
  say "${RULESET_TOOL} is missing or cut short"
  if tool_whole "$TOOL_LAST_GOOD" && install_tool "$TOOL_LAST_GOOD"; then
    say "restored it from its last good copy"
    return 0
  fi
  say "no last good copy of it: asking metadata for one"
  # A file by name, which curl starts over on a retry: on stdout, a first try that
  # stalled would leave its part in front of the whole.
  curl -fsS --retry 5 --retry-connrefused --max-time 30 -H 'Metadata-Flavor: Google' \
    -o "$fetched" "$TOOL_IN_METADATA" 2>/dev/null || say "metadata has no watchtower-ruleset to give, or didn't answer"
  chmod 0700 "$fetched" 2>/dev/null
  if [[ -s "$fetched" ]] && tool_self_check "$fetched" && install_tool "$fetched"; then
    say "restored it from metadata"
    return 0
  fi
  say "could not restore it: sshd's gate needs it, so sshd isn't asked for"
  return 1
}

# fall_back: its last good copy in place of a tool that failed, if there's one that
# differs. True when it's in place.
fall_back() {
  tool_whole "$TOOL_LAST_GOOD" || return 1
  cmp -s "$TOOL_LAST_GOOD" "$RULESET_TOOL" && return 1
  say "${RULESET_TOOL} failed: falling back to its last good copy"
  install_tool "$TOOL_LAST_GOOD"
}

# apply_tool: the tool's own way to sshd, through its gate. Exits here when a rollback
# finished and the VM is rebooting; else apply's exit status.
apply_tool() {
  local rc
  "$RULESET_TOOL" apply 2>&1 | quote
  rc=${PIPESTATUS[0]}
  if [[ "$rc" -eq "$RULESET_REBOOTING" ]]; then
    say "a rollback finished: rebooting, and this script runs once more"
    exit 0
  fi
  return "$rc"
}

# Only the tool starts sshd, through its gate. With no usable tool, sshd isn't asked
# for at all: nothing would gate it.
ask_for_sshd() {
  if ! tool_whole "$RULESET_TOOL"; then
    say "no usable ${RULESET_TOOL}: loading the guard, and not asking for sshd, as nothing would gate it (rerun scripts/bootstrap.sh)"
    systemctl start nftables.service 2>&1 | quote
    return 0
  fi
  if ! apply_tool && fall_back; then
    apply_tool || true
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
  # For a tool from metadata, and its self-check's floor: in /run, as the disk may be
  # full.
  work="$(mktemp -d -p /run bastion-recovery.XXXXXX)" || work=/run
  trap '[[ "$work" == /run ]] || rm -rf "$work"' EXIT
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
