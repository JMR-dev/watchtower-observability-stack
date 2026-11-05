#!/usr/bin/env bash
# What a trial of a new ruleset (config/bastion/ruleset.sh, end_logins) does to real
# logins, under real systemd, logind and sshd, in Debian 13, which scripts/check-bastion.sh
# can't show with systemctl stubbed: nothing of a login's from before the load can
# confirm the new ruleset, and a new login still can.
#
#   a real session   a process ignoring TERM and HUP is gone, and a new login confirms
#   a root session   a stop that would take its time doesn't hold up a new login
#   a chain of forks, each trying to confirm and starting the next, so that a scan of
#                    /proc is always a step behind: dies, and confirms nothing
#   a connection in pre-auth across the trial, which ssh.service's KillMode=process
#                    leaves running: dies, and confirms nothing
#   a login's nonce  the name of the file a login leaves reaches watchtower/login, as
#                    scripts/bootstrap.sh's per-run login check needs
#   no change        a boot with no ruleset change touches no one's session
#   no user namespaces, the container's limit at 0: a user can't make one, and a trial,
#                    a login and its confirmation still work, as none of them needs one
#
#   scripts/check-bastion-sessions.sh
#
# Podman, and not in CI: it runs systemd as PID 1 in a privileged container, in podman's
# own user namespace, which Docker-in-Docker runners don't give. Run it by hand after a
# change to end_logins. Only the metadata server is stubbed. Keys are throwaway, made in
# the container and never printed. Files go in with `cp`. Touches a local image and a
# container, both named bastion-sessions and both removed on exit. No GCP.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="localhost/bastion-sessions:check"
name="bastion-sessions"
# The same Debian 13 scripts/check-bastion.sh pins.
# shellcheck disable=SC2016 # sed's pattern, not the shell's
base="$(sed -n 's/^DEBIAN_IMAGE="${DEBIAN_IMAGE:-\(.*\)}"$/\1/p' "${repo_root}/scripts/check-bastion.sh")"

work=""
remove_container() {
  podman rm -f "$name" "${name}-build" >/dev/null 2>&1 || true
  podman rmi -f "$image" >/dev/null 2>&1 || true
}
cleanup() {
  remove_container
  rm -rf "$work"
}
trap cleanup EXIT
# Anything an earlier run left.
remove_container
work="$(mktemp -d)"

cat >"${work}/inside.sh" <<'INSIDE'
# No set -e: a check failing is a result, and the next must still run.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
TOOL=/usr/local/sbin/watchtower-ruleset
DROPBOX=/run/watchtower-ruleset
RULES=/rulesets
USER_NAME=a-user
USER_UID=5000
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=20 -o BatchMode=yes -i /stubs/key)

fail=0
pass() { echo "ok    $*"; }
flunk() { echo "FAIL  $*"; fail=1; }
# check <name> <command...>
check() {
  local name=$1
  shift
  if "$@"; then pass "$name"; else flunk "$name"; fi
}
refute() {
  local name=$1
  shift
  if "$@"; then flunk "$name"; else pass "$name"; fi
}

login() { ssh "${SSH_OPTS[@]}" "${USER_NAME}@127.0.0.1" "$@"; }
word_is() { grep -q "^$1 " /stubs/attr.ruleset 2>/dev/null; }
# wait_word <word> <seconds>
wait_word() {
  local i
  for ((i = 0; i < $2; i++)); do
    word_is "$1" && return 0
    sleep 1
  done
  return 1
}
users_processes() { pgrep -u "$USER_UID" -c; }
none_of_the_users() { [[ "$(users_processes)" == 0 ]]; }
no_jobs() { [[ -z "$(systemctl list-jobs --no-legend --no-pager)" ]]; }
sshd_is_up() { [[ "$(systemctl is-active ssh.service)" == active ]]; }
# A ruleset the kernel hasn't had yet, each time, so that each is a trial.
next_ruleset=0
trial() {
  next_ruleset=$((next_ruleset + 1))
  { cat /check/nftables.conf; echo "# ${next_ruleset}"; } >"${RULES}/${next_ruleset}"
  rm -f /stubs/attr.ruleset
  "$TOOL" apply "${RULES}/${next_ruleset}" "try-${next_ruleset}" >/dev/null 2>&1
}
# A trial confirmed, so the next check starts clean.
settle() {
  trial
  login "touch ${DROPBOX}/settle"
  wait_word confirmed 10
}
clear_user() {
  systemctl stop "user-${USER_UID}.slice" 2>/dev/null
  for _ in $(seq 20); do
    pkill -KILL -u "$USER_UID" 2>/dev/null || break
    sleep 0.1
  done
  find "$DROPBOX" -mindepth 1 -delete
}

prepare() {
  mkdir -p /stubs "$RULES"
  chmod 0755 /stubs
  cat >/usr/local/bin/curl <<'STUB'
#!/bin/bash
# Stands in for the metadata server: a PUT's value goes in a file named by its key,
# anything else answers 200, as for a VM with an account.
args=("$@")
for ((i = 0; i < $#; i++)); do
  if [[ "${args[i]}" == --data ]]; then
    printf '%s\n' "${args[i + 1]}" >"/stubs/attr.${args[$# - 1]##*/}"
    exit 0
  fi
done
echo 200
STUB
  chmod 0755 /usr/local/bin/curl
  install -m 0755 /check/ruleset.sh "$TOOL"
  "$TOOL" setup >/dev/null 2>&1
  systemctl start watchtower-ruleset-confirm.path
  cp /check/nftables.conf /etc/nftables.conf
  systemctl restart nftables.service
  useradd -m -u "$USER_UID" -s /bin/bash "$USER_NAME"
  usermod -p '*' "$USER_NAME"
  ssh-keygen -q -t ed25519 -N '' -f /stubs/key
  # A key with a passphrase, whose askpass waits: its login sits in pre-auth until then.
  ssh-keygen -q -t ed25519 -N 'stand-in-passphrase' -f /stubs/slow-key
  install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "/home/${USER_NAME}/.ssh"
  cat /stubs/key.pub /stubs/slow-key.pub >"/home/${USER_NAME}/.ssh/authorized_keys"
  chown "$USER_NAME:$USER_NAME" "/home/${USER_NAME}/.ssh/authorized_keys"
  cat >/stubs/slow-askpass <<'ASK'
#!/bin/bash
sleep 8
echo stand-in-passphrase
ASK
  chmod 0755 /stubs/slow-askpass
  # Each generation ignores TERM and HUP, tries to confirm, starts the next and exits.
  cat >/stubs/chain.sh <<'CHAIN'
#!/bin/bash
trap '' TERM HUP
: >/run/watchtower-ruleset/chain 2>/dev/null
bash /stubs/chain.sh </dev/null >/dev/null 2>&1 &
disown
exit 0
CHAIN
  chmod 0755 /stubs/chain.sh
  systemctl restart ssh.service
}

prepare
# Without these the rest says nothing about real sessions.
if [[ "$(systemctl is-active systemd-logind.service)" != active ]] || ! login true; then
  flunk "logind isn't running here, or a login doesn't work: nothing below would mean anything"
  exit 1
fi
check "a login is in a session of its own" grep -q "/user.slice/user-${USER_UID}.slice/session-" <<<"$(login 'cat /proc/self/cgroup')"

# A real session.
settle
login 'setsid bash -c "trap \"\" TERM HUP; exec sleep 900" </dev/null >/dev/null 2>&1 &'
sleep 1
refute "a real session: running before the trial" none_of_the_users
trial
check "a real session: says pending" word_is pending
check "a real session: nothing of the user's is left" none_of_the_users
check "a real session: sshd is back" sshd_is_up
check "a real session: no stop still running" no_jobs
login "touch ${DROPBOX}/new"
check "a real session: a new login confirms" wait_word confirmed 8
clear_user

# A root session, whose stop would take its time: a new login doesn't wait for it.
settle
systemd-run --quiet --scope --slice=user-0.slice --unit=check-root-session.scope \
  -p TimeoutStopSec=40 setsid bash -c 'trap "" TERM HUP; exec sleep 900' </dev/null >/dev/null 2>&1 &
sleep 1
trial
check "a root session: says pending" word_is pending
check "a root session: no stop left waiting on it" no_jobs
login "touch ${DROPBOX}/during"
check "a root session: a new login confirms" wait_word confirmed 8
clear_user

# A chain of forks.
settle
systemctl stop watchtower-ruleset-confirm.path
login 'setsid bash /stubs/chain.sh </dev/null >/dev/null 2>&1 &'
sleep 1
find "$DROPBOX" -mindepth 1 -delete
systemctl start watchtower-ruleset-confirm.path
trial
check "a chain of forks: says pending" word_is pending
sleep 3
check "a chain of forks: none left" none_of_the_users
check "a chain of forks: can't confirm, with no new login" word_is pending
check "a chain of forks: the rollback stands" test "$(systemctl is-active watchtower-ruleset-rollback.timer)" = active
login "touch ${DROPBOX}/new"
check "a chain of forks: a new login confirms" wait_word confirmed 8
clear_user

# A connection in pre-auth across the trial.
settle
SSH_ASKPASS=/stubs/slow-askpass SSH_ASKPASS_REQUIRE=force \
  setsid ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i /stubs/slow-key \
  "${USER_NAME}@127.0.0.1" "touch ${DROPBOX}/from-before-the-load" </dev/null >/dev/null 2>&1 &
client=$!
sleep 2
check "pre-auth: held open before the trial" test "$(pgrep -c -f sshd-session)" -ge 1
trial
check "pre-auth: says pending" word_is pending
check "pre-auth: its connection is gone" test "$(pgrep -c -f sshd-session)" = 0
wait "$client"
refute "pre-auth: its client fails" test "$?" = 0
refute "pre-auth: can't confirm" wait_word confirmed 3
login "touch ${DROPBOX}/new"
check "pre-auth: a new login confirms" wait_word confirmed 8
clear_user

# A login asked for by a nonce, as scripts/bootstrap.sh asks: its file's name reaches
# watchtower/login through the real path unit, and a plain login after it keeps it there.
settle
login_nonce="$(printf '%032x' 4660)"
login "touch ${DROPBOX}/confirm-${login_nonce}"
sleep 2
check "a login's nonce: in the login attribute" grep -q " for ${login_nonce} run " /stubs/attr.login
login "touch ${DROPBOX}/plain"
sleep 2
check "a login's nonce: still there after a plain login" grep -q " for ${login_nonce} run " /stubs/attr.login
clear_user

# No change: the same file again, at a boot, touches no one's session.
settle
login 'setsid sleep 900 </dev/null >/dev/null 2>&1 &'
sleep 1
sessions_before="$(loginctl list-sessions --no-legend --no-pager | wc -l)"
"$TOOL" apply /etc/nftables.conf >/dev/null 2>&1
refute "no change: the user's process is still there" none_of_the_users
check "no change: sshd is up" sshd_is_up
check "no change: the sessions are all there" test "$(loginctl list-sessions --no-legend --no-pager | wc -l)" = "$sessions_before"
clear_user

# No user namespaces at all: this container's own limit at 0, which stops root and
# systemd too, so it's stricter than the bastion's kernel.unprivileged_userns_clone=0
# (that knob is Debian's, and this kernel is the host's). A trial, a login and its
# confirmation need none, and a user can't make one. Only where the limit can be set,
# and only if a user could make one before, or the refusal would show nothing.
settle
userns_limit="$(cat /proc/sys/user/max_user_namespaces 2>/dev/null)"
if ! runuser -u "$USER_NAME" -- unshare --user true 2>/dev/null; then
  echo "skip  no user namespaces: a user can't make one here even with the limit as it is"
elif ! echo 0 >/proc/sys/user/max_user_namespaces 2>/dev/null; then
  echo "skip  no user namespaces: this container can't set user.max_user_namespaces"
else
  refute "no user namespaces: a user can't make one" runuser -u "$USER_NAME" -- unshare --user true
  check "no user namespaces: a login works" login true
  trial
  check "no user namespaces: a trial says pending" word_is pending
  check "no user namespaces: sshd is back" sshd_is_up
  login "touch ${DROPBOX}/new"
  check "no user namespaces: a new login confirms" wait_word confirmed 8
  echo "$userns_limit" >/proc/sys/user/max_user_namespaces
  clear_user
fi
exit "$fail"
INSIDE

podman run --name "${name}-build" "$base" bash -c \
  'apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus libpam-systemd nftables openssh-server openssh-client iproute2 procps >/dev/null'
podman commit -q "${name}-build" "$image" >/dev/null
podman rm -f "${name}-build" >/dev/null

podman run -d --name "$name" --systemd=always --memory 1g --privileged \
  --security-opt label=disable "$image" /lib/systemd/systemd >/dev/null
podman exec "$name" mkdir -p /check
for file in ruleset.sh nftables.conf; do
  podman cp "${repo_root}/config/bastion/${file}" "${name}:/check/"
done
podman cp "${work}/inside.sh" "${name}:/check/inside.sh"

for _ in $(seq 40); do
  case "$(podman exec "$name" systemctl is-system-running 2>/dev/null || true)" in
    running | degraded) break ;;
  esac
  sleep 2
done

podman exec "$name" bash /check/inside.sh
