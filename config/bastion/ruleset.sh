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
#   floor-rules      Prints it, loading nothing.
#   loaded           Is the guard in the kernel, by its rules and not its name?
#   refuses-users    Does a user fail to connect to the metadata server's port 80?
#                    Only a connection, which sends nothing: for when the network
#                    is up.
#   probe <file>     What the throwaway namespace of step 1 below runs.
#
# apply, on a ruleset that differs from /etc/nftables.conf:
#
#   1. Loads it in a network namespace of its own, where nothing can see it, and
#      refuses it unless it does a guard's job there: with the metadata server's
#      addresses on lo and something listening, root connects and a user doesn't.
#   2. Keeps the old file, unless a trial is already running (an unconfirmed
#      ruleset is nobody's way back) or the old file no longer loads.
#   3. Records it as pending, on disk, and arms the 10-minute timer. The timer
#      is enabled and conditional on the record, so a reboot while pending
#      re-arms it even if the startup script never gets this far.
#   4. Installs it, stops sshd, and has the kernel kill everything under user.slice
#      and under ssh.service, connections still in pre-auth among them, then anything
#      else at a login's uid. So no login's process or connection from before the
#      load is left to confirm it. Then it loads it. One that won't load, or that has
#      no guard after all, rolls back at once. A boot with no change touches no one's
#      session. This keeps out what's left of a login, not root: a root process
#      outside those two groups could confirm, as it could do anything else.
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
# flooding the directory confirms at the first file. A trial ends what's running
# and empties the directory once it's loaded, so a login from before the load
# confirms nothing. And nothing of a user's runs without a login (setup), so
# nothing confirms without one. Each time, confirm also tells the guest attribute
# watchtower/login, as scripts/bootstrap.sh's proof that someone got in.
#
# The first install has no old ruleset. The VM has no account yet, so no token
# to guard: rollback puts back what was there, the package's empty ruleset, and
# sshd still runs, on the floor. Step 7 then stops, with the VM running as no
# one.
#
# Each outcome, at every boot again, is a line on the serial console for whoever
# reads it, and the guest attribute watchtower/ruleset for scripts/bootstrap.sh:
#
#   pending|confirmed|rolled back|refused|failed <sha256> at <epoch> boot <boot id> run <nonce>
#
# confirmed: this ruleset is on and sshd is active, at this boot. failed: it should
# be on and isn't, sshd won't start, or a rollback's restore hasn't worked yet.
# watchtower/boot is this boot's id, from the kernel, as `<boot id> run <nonce>`, and
# watchtower/login is
#
#   login <epoch> boot <boot id> for <login nonces, comma-separated, or -> run <nonce>
#
# and watchtower/tool, which startup.sh says at each boot, is
#
#   <sha256 of the installed tool> boot <boot id> run <nonce>
#
# said again here with every confirmed, from the copy startup.sh keeps once this boot's
# apply has ended well, so a lost word comes back with a login; with no copy, nothing.
#
# The run nonce (the owner's decision, 2026-11-04) is the one bootstrap put in metadata
# while the VM was stopped, which startup.sh keeps in /run for root alone, or "-" for
# none. A value written on a boot that had no guard, where any user could write one,
# carries an earlier start's nonce, so bootstrap takes it for no word. The login
# nonces are those in the names of the files logins left (confirm-<nonce>, from
# scripts/bastion-confirm.sh), this boot's last eight: bootstrap's own shows that a
# login of this run got in.
#
# bootstrap can't go by the console, as any user can put a line there (logger,
# through rsyslog). The guard keeps them from the attributes.
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
# The last thing this boot said of its ruleset.
LAST_WORD="/run/watchtower-ruleset.word"
# This boot's run nonce, which startup.sh keeps (it's in metadata).
RUN_NONCE="/run/watchtower-run-nonce"
# The login nonces this boot has seen.
LOGINS="/run/watchtower-ruleset.logins"
# How many it keeps.
LOGINS_KEPT=8
# The watchtower/tool word startup.sh said at this boot, once this boot's apply ended
# well (its report_tool): what say_tool says again, and nothing else.
TOOL_WORD="/run/watchtower-ruleset.tool"
# This boot's apply went through to its end, confirmed (mark_applied): its own marker,
# which nothing else writes, for startup.sh's tool_proved.
APPLIED="/run/watchtower-ruleset.applied"
# systemd's own name for a mount there.
DROPBOX_MOUNT='run-watchtower\x2druleset.mount'
TOOL="/usr/local/sbin/watchtower-ruleset"
TIMER="watchtower-ruleset-rollback.timer"
ROLLBACK="watchtower-ruleset-rollback.service"
ACCOUNT_URL="http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email"
ATTRIBUTES_URL="http://169.254.169.254/computeMetadata/v1/instance/guest-attributes/watchtower"
METADATA_V4="169.254.169.254"
METADATA_V6="fd20:ce::254"
# Logins' uids start here (OS Login's are far above it). Below it are root and the
# VM's own daemons, which a trial leaves alone.
LOGIN_UID_MIN=1000
# The uid a guard is tried against, in the namespace and on the real address.
PROBE_UID=65534
# apply's exit status when it rolled back and is rebooting.
REBOOTING=75
# Set when this boot's ruleset is on with nothing left to try: cmd_apply says
# confirmed once sshd is active too.
confirmed_sha=""

say() { printf 'bastion: %s\n' "$*"; }
warn() { printf 'bastion: warning: %s\n' "$*" >&2; }

boot_id() { cat /proc/sys/kernel/random/boot_id; }

# This boot's run nonce, or "-" when it has none.
run_nonce() {
  local nonce
  nonce="$(cat "$RUN_NONCE" 2>/dev/null)" || nonce=""
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || nonce=-
  printf '%s' "$nonce"
}

# put_raw <key> <value>: the guest attribute watchtower/<key>, as it is.
put_raw() {
  curl -fsS -o /dev/null --max-time 5 --retry 2 --retry-connrefused -X PUT -H 'Metadata-Flavor: Google' \
    --data "$2" "${ATTRIBUTES_URL}/$1"
}

# put_attribute <key> <value>: with this boot's run nonce after it.
put_attribute() { put_raw "$1" "$2 run $(run_nonce)"; }

# logins_seen: the login nonces in the names of the files in the dropbox now, kept with
# this boot's others, the newest last and LOGINS_KEPT at most; prints them
# comma-separated, or "-". Only a name of exactly that shape counts, so nothing else a
# user names a file reaches the attribute. Never reads a file.
logins_seen() {
  local name nonce i joined seen=()
  if [[ -f "$LOGINS" ]]; then
    while IFS= read -r nonce; do
      [[ ! "$nonce" =~ ^[0-9a-f]{32}$ ]] || seen+=("$nonce")
    done <"$LOGINS"
  fi
  while IFS= read -r -d '' name; do
    nonce="${name#confirm-}"
    [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || continue
    for i in "${!seen[@]}"; do
      [[ "${seen[i]}" != "$nonce" ]] || unset 'seen[i]'
    done
    seen+=("$nonce")
  done < <(find "$DROPBOX" -mindepth 1 -maxdepth 1 -name 'confirm-*' -printf '%f\0' 2>/dev/null)
  seen=("${seen[@]}")
  [[ "${#seen[@]}" -le "$LOGINS_KEPT" ]] || seen=("${seen[@]: -$LOGINS_KEPT}")
  (umask 077 && printf '%s\n' "${seen[@]}" >"$LOGINS") || warn "could not keep this boot's login nonces"
  if [[ "${#seen[@]}" -eq 0 ]]; then
    printf '%s' -
  else
    joined="$(printf '%s,' "${seen[@]}")"
    printf '%s' "${joined%,}"
  fi
}

# status <state> <sha>: what came of it. The boot's id tells scripts/bootstrap.sh
# this boot's from an earlier one's, which the attribute outlasts. Telling it never
# changes what came of it. The state is kept for this boot too, whether or not the
# attribute took it, for cmd_confirm to know what it may say again.
status() {
  local value
  value="$1 $2 at $(date +%s) boot $(boot_id)"
  say "ruleset ${value}"
  printf '%s\n' "$1" >"$LAST_WORD" || true
  put_attribute ruleset "$value" || warn "could not put that in the guest attribute"
}

sshd_active() { systemctl is-active --quiet ssh.service; }

# say_tool: watchtower/tool again, word for word as startup.sh's report_tool said it at
# this boot, from the copy it keeps in TOOL_WORD: bootstrap's final check asks for it.
# Said again with every confirmed, so a word the attribute lost comes back with a
# login. With no such copy it says nothing: report_tool keeps one only once this boot's
# apply has ended well, so a login can't vouch for a tool whose apply never finished.
# Never fails.
say_tool() {
  local word
  word="$(cat "$TOOL_WORD" 2>/dev/null)" || return 0
  [[ "$word" =~ ^[0-9a-f]{64}\ boot\ [0-9a-f-]+\ run\ ([0-9a-f]{32}|-)$ ]] || return 0
  put_raw tool "$word" || warn "could not put the tool in the guest attribute"
}

# say_confirmed <sha>: confirmed means the way in works too.
say_confirmed() {
  if sshd_active; then
    status confirmed "$1"
    say_tool
  else
    warn "the ruleset is confirmed, and sshd isn't active"
    status failed "$1"
  fi
}

# guard_rules_ok <the table as nft lists it>: every way to the metadata server goes
# through a chain that refuses every uid but root, and lets through nothing but
# named ports, and not the token's. Weaker than the namespace's test of what a file
# does, which only a new file gets, but it needs no network, so it can run before
# every start of sshd.
guard_rules_ok() {
  [[ "$1" == *"hook output"* &&
    "$1" == *"ip daddr ${METADATA_V4} jump metadata"* &&
    "$1" == *"ip6 daddr ${METADATA_V6} jump metadata"* ]] || return 1
  printf '%s\n' "$1" | awk '
    /^[[:space:]]*chain / { chain = $2; next }
    /^[[:space:]]*}/ { chain = ""; next }
    chain == "output" && /accept|return|goto/ && !/policy accept/ { bad = 1 }
    chain == "metadata" && /meta skuid != 0 .*reject/ { refuses = 1; next }
    chain == "metadata" && /accept|return|jump|goto/ && (!/dport/ || /[ {]80[ ,}]/) { bad = 1 }
    END { exit !(refuses && !bad) }'
}

# The guard in the kernel, by what it says rather than by its name.
guard_loaded() {
  local listed
  listed="$(nft list table inet metadata_guard 2>/dev/null)" || return 1
  guard_rules_ok "$listed"
}

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

# guards <file>: this file loads, and does a guard's job, whatever its comments
# say: guard_probe, in that namespace.
guards() { unshare --net bash "${BASH_SOURCE[0]}" probe "$1"; }

# connects <address>: root gets a connection to its port 80. Sends nothing.
connects() {
  # shellcheck disable=SC2016 # for the inner shell
  timeout 3 bash -c 'exec 3<>"/dev/tcp/$1/80"' bash "$1" 2>/dev/null
}

# connects_as_user <address>: the same as the uid a guard is tried against.
connects_as_user() {
  # shellcheck disable=SC2016 # for the inner shell
  setpriv --reuid="$PROBE_UID" --regid="$PROBE_UID" --clear-groups \
    timeout 3 bash -c 'exec 3<>"/dev/tcp/$1/80"' bash "$1" 2>/dev/null
}

# guard_behaves <metadata address>...: with something already listening there and
# on loopback. A user's connection to loopback shows the test itself works, as a
# user's failing for any other reason would look the same as a guard refusing.
guard_behaves() {
  local address reached=""
  # The listener may take a moment.
  for _ in $(seq 30); do
    if connects 127.0.0.1; then
      reached=1
      break
    fi
    sleep 0.1
  done
  [[ -n "$reached" ]] || { warn "the guard's test has nothing listening"; return 1; }
  connects_as_user 127.0.0.1 || { warn "the guard's test can't connect as a user at all"; return 1; }
  for address in "$@"; do
    connects "$address" || { warn "root can't reach ${address} under this ruleset"; return 1; }
    if connects_as_user "$address"; then
      warn "a user reaches ${address} under this ruleset"
      return 1
    fi
  done
}

# Runs in the namespace guards makes, so nothing here touches the real server: its
# addresses, on lo here, answer whatever listens on them.
guard_probe() {
  local file=$1 listener rc=0
  local addresses=("$METADATA_V4")
  local listen=(-l 127.0.0.1:80 -l "${METADATA_V4}:80")
  nft --file "$file" || return 1
  guard_loaded || { warn "this ruleset gives no guard"; return 1; }
  ip link set lo up || return 1
  ip addr add "${METADATA_V4}/32" dev lo || return 1
  # Where there's IPv6 at all.
  if ip -6 addr add "${METADATA_V6}/128" dev lo nodad 2>/dev/null; then
    addresses+=("$METADATA_V6")
    listen+=(-l "[${METADATA_V6}]:80")
  fi
  # Listens on all of them, and at the first connection runs sleep with them open.
  systemd-socket-activate "${listen[@]}" sleep 60 >/dev/null 2>&1 &
  listener=$!
  guard_behaves "${addresses[@]}" || rc=1
  kill "$listener" 2>/dev/null || true
  wait "$listener" 2>/dev/null || true
  return "$rc"
}

# The guard at its smallest (config/bastion/nftables.conf's rules, and
# scripts/check-bastion.sh keeps them equal), for when no file will do. It can't
# lock anyone out, since it only ever touches the way to the metadata server,
# and it needs nothing on disk. floor-rules prints it, for startup.sh's and
# recovery.sh's self-check of a new copy of this tool.
floor() { floor_rules | nft --file -; }

floor_rules() {
  cat <<'NFT'
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

# Ends sshd and everything of a login's, so only a login after the load can confirm
# it: a process from before would otherwise do so with no one able to get in. Only
# for a trial. cmd_apply starts sshd again once it's loaded.
end_logins() {
  local proc uid found
  systemctl stop ssh.service || warn "could not stop sshd"
  # Sessions and user managers, with root's shells among them.
  systemctl --no-block stop user.slice || warn "could not end the login sessions"
  # At once, by the kernel, so no chain of forks can outrun it. Debian's ssh.service
  # has KillMode=process, so its stop leaves connections still in pre-auth running,
  # and they can log in afterwards. No cgroup there (not a real boot) is nothing to do.
  { echo 1 >/sys/fs/cgroup/user.slice/cgroup.kill; } 2>/dev/null || true
  { echo 1 >/sys/fs/cgroup/system.slice/ssh.service/cgroup.kill; } 2>/dev/null || true
  # Whatever is left at a login's uid, in any other cgroup.
  for _ in 1 2 3 4 5; do
    found=""
    for proc in /proc/[0-9]*; do
      uid="$(stat -c %u "$proc" 2>/dev/null)" || continue
      [[ "$uid" -ge "$LOGIN_UID_MIN" ]] || continue
      if kill -KILL "${proc##*/}" 2>/dev/null; then found=1; fi
    done
    [[ -n "$found" ]] || break
    sleep 0.2
  done
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
  end_logins
  if ! load_ruleset; then
    warn "the new ruleset did not load or has no guard: rolling back now"
    end_trial
    return
  fi
  # A login's file from before this one, which may be queued behind this lock.
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
      confirmed_sha="$sha"
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
      confirmed_sha="$sha"
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
  # First, so that a boot that gets no further still says it's a new one.
  put_attribute boot "$(boot_id)" || warn "could not put this boot's id in the guest attribute"
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
  if ! gate; then
    [[ -z "$confirmed_sha" ]] || status failed "$confirmed_sha"
    systemctl stop ssh.service || true
    say "error: sshd stays down: the way back is new metadata; the serial console only shows this (docs/runbook.md, \"The bastion with SSH gone\")"
    exit 1
  fi
  systemctl reset-failed ssh.service 2>/dev/null || true
  if ! systemctl start ssh.service || ! sshd_active; then
    [[ -z "$confirmed_sha" ]] || status failed "$confirmed_sha"
    say "error: sshd did not start, with the guard on: journalctl -u ssh says why (docs/runbook.md, \"The bastion with SSH gone\")"
    exit 1
  fi
  if [[ -n "$confirmed_sha" ]]; then
    status confirmed "$confirmed_sha"
    mark_applied
  fi
}

# mark_applied: this apply went through to its end with its ruleset confirmed and sshd
# up, as `confirmed <sha256 of the code that ran>`: what startup.sh's tool_proved asks
# before it keeps a tool as the last good copy. Written here alone, never by confirm,
# rollback or any say_: the word in LAST_WORD is any of those's too, and a login's
# confirm during a do-nothing apply would say confirmed there for it. Root's alone.
mark_applied() {
  local sha
  sha="$(sha256sum <"${BASH_SOURCE[0]}" | cut -d' ' -f1)" || return 0
  rm -f "$APPLIED"
  (umask 077 && printf 'confirmed %s\n' "$sha" >"$APPLIED") || warn "could not mark this apply as done"
}

# A word the attribute lost, at a boot or a confirmation, stays lost for the whole
# boot unless something says it again. With nothing pending, the file on disk the
# confirmed one, its guard on and sshd up, confirmed is still true. Never over a
# rolled back or refused of this boot: that's about the file in metadata, and it has
# to reach bootstrap.
say_confirmed_again() {
  local confirmed
  confirmed="$(read_state "$CONFIRMED")"
  [[ -n "$confirmed" && -f "$RULESET" && "$(sha_of "$RULESET")" == "$confirmed" ]] || return 0
  case "$(read_state "$LAST_WORD")" in
    "rolled back" | refused) return 0 ;;
  esac
  if guard_loaded && sshd_active; then
    status confirmed "$confirmed"
    say_tool
  fi
}

cmd_confirm() {
  local pending logins
  lock
  # A file from before the load went with the load (try).
  [[ -n "$(find "$DROPBOX" -mindepth 1 -print -quit 2>/dev/null)" ]] || return 0
  # What a file there shows at any time: someone got in, on this boot, and which
  # logins that were asked for by a nonce did.
  logins="$(logins_seen)" || logins=-
  put_attribute login "login $(date +%s) boot $(boot_id) for ${logins}" || warn "could not put the login in the guest attribute"
  pending="$(read_state "$PENDING")"
  # Not if it's rejected already, with its rollback still trying to reach the disk.
  if [[ -n "$pending" && ! -e "${REJECTED}/${pending}" ]]; then
    # The files stay until this is on disk: a login on a full disk counts once
    # there's room. The path unit comes back as soon as this ends, hence the pause.
    if ! write_state "$CONFIRMED" "$pending" || ! rm -f "$PENDING"; then
      warn "could not record the confirmation (is the disk full?): this tries again until the rollback fires"
      sleep 5
      return 0
    fi
    sync
    systemctl stop "$TIMER" || true
    say_confirmed "$pending"
  elif [[ -z "$pending" ]]; then
    say_confirmed_again
  fi
  # By name, never following anything a user left here.
  find "$DROPBOX" -mindepth 1 -delete 2>/dev/null || true
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
  # crontab, no at job and no lingering, and any left from before go. at's spool
  # is there only if the package is, and its jobs and spool files go by their owner.
  printf 'root\n' | put /etc/cron.allow
  printf 'root\n' | put /etc/at.allow
  find /var/spool/cron/crontabs -mindepth 1 ! -name root -delete 2>/dev/null || true
  find /var/spool/cron/atjobs /var/spool/cron/atspool -mindepth 1 ! -user root -delete 2>/dev/null || true
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
    floor-rules) floor_rules ;;
    loaded) guard_loaded ;;
    refuses-users) ! connects_as_user "$METADATA_V4" ;;
    probe) guard_probe "$@" ;;
    *) echo "usage: watchtower-ruleset setup|apply|gate|confirm|rollback|floor|floor-rules|loaded|refuses-users|probe" >&2; exit 2 ;;
  esac
}

main "$@"
