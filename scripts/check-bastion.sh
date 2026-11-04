#!/usr/bin/env bash
# Tests the break-glass bastion's startup pieces (config/bastion/) in Debian
# 13, the bastion's own release, since the only other place they run is the
# VM itself:
#
#   peer   startup.sh's check_peer on made-up configs (all-zero dummy keys):
#          it takes wg-easy's agent config as it is, adds a missing MTU and
#          keepalive, drops DNS, writes the rest afresh, and refuses hooks,
#          Table, FwMark, SaveConfig, more routes, a second peer or none, any
#          other setting and any malformed key, however its whitespace hides
#          them from all but wg, without echoing the config.
#   apt    startup.sh recovers from an install a stop interrupted, and main
#          prints what bootstrap.sh waits for only after apt is done.
#   userns startup.sh turns unprivileged user namespaces off with Debian's own knob,
#          for good and at once, before the guard, and warns rather than fails on a
#          kernel without it. This container's kernel is the host's, so only the VM
#          shows the knob itself.
#   fetch  only a missing or empty secret takes telemetry down: any other
#          failure to read it, and a config that fails its checks, leave the
#          tunnel and Alloy as they are.
#   ping   startup.sh pings its Healthchecks.io check only with the guard loaded
#          and sshd active, with a stand-in for the URL: it reaches curl on stdin,
#          never an argument or any output, only a URL of Healthchecks.io's shape
#          is sent, and no failure stops anything else.
#   guard  nftables.conf checked, loaded twice (a reload, as at boot), and
#          probed on 169.254.169.254 (on lo): root reaches it over HTTP,
#          other uids are refused at once, and every uid still reaches its
#          DNS (53), DHCP (67) and NTP (123), and everything else. The same
#          on its IPv6 address, fd20:ce::254, where the container has IPv6.
#   ruleset  ruleset.sh's dead man's switch, on real nft with systemctl and the
#          metadata server stubbed: arm, confirm, fire, rejected, re-arm after
#          a reboot, first install, a retry, a guard that won't load or lets a user
#          through, a process from before the load, a disk that won't take a
#          restore (a full tmpfs too), the floor, what a non-root user can do,
#          and the guest attributes bootstrap.sh reads, through its own
#          ruleset_state, login_seen and waits. Its units are checked by
#          systemd-analyze verify. Cron refuses a user, a crontab or at job left
#          from before is gone, and polkit's rule runs under its own JavaScript
#          engine.
#   bootstrap  bootstrap.sh's bastion_update in order, with gcloud stubbed: metadata
#          before a stop, a fresh run nonce while stopped for each start, the VM
#          started again by its exit trap if a stop is left in flight, a login last,
#          and the final check, which wants this run's nonces and this ruleset.sh.
#   nonce  the run nonce: startup.sh keeps only one of its shape, for root alone,
#          and every attribute carries it; bootstrap counts only its own, so a value
#          planted on an unguarded boot, with that boot's nonce, is no word. The
#          login nonce: confirm lists only names of exactly its shape, eight at most,
#          and bootstrap counts only a login of its own run.
#   tool   startup.sh's self-check of a new ruleset.sh, in a network namespace of its
#          own, refuses a tool whose gate says yes with no guard, that takes no rules
#          for a guard, or whose floor doesn't guard or won't load, or one cut short;
#          a tool that passes it and brings sshd up becomes the last good copy, one
#          that fails at a boot gives way to that copy, and none that failed the
#          self-check ever runs. sshd only ever starts through the gate.
#   recovery  recovery.sh, the one-off startup script for when SSH is gone: it
#          changes nothing on a healthy bastion, frees a full disk without touching
#          a user's files, a rollback the disk held up then finishes, and a tool cut
#          short comes back from its last good copy, or from metadata if that passes
#          the self-check. It never gets sshd past the gate, and with no tool it
#          never asks for sshd at all, even with sshd's drop-in gone.
#
#   scripts/check-bastion.sh            # docker; CONTAINER_RUNTIME=podman locally
#
# A container has no systemd running and no GCE, so only the real VM can show:
# that the path unit and the timer fire (at the 10 minutes, and again after a
# reboot), that a login's file reaches confirm, that the two services' lines
# reach the serial console, that sshd's drop-in holds it back and the guest
# agent's restarts get past it, that a package upgrade's restart keeps both up,
# that the metadata server says 404 for a VM with no account, that it takes the
# guest attribute from root, that the dropbox's tmpfs comes up, that a ruleset
# that won't load brings the floor before the network, that polkit refuses a
# user lingering, that the real rollback reboots into the old ruleset, that the
# ping reaches Healthchecks.io and the timer fires, and that the guest agent runs
# recovery.sh from metadata, on a full disk above all.
#
# Needs the network (apt, inside the container). Files go in with `cp`, not
# a bind mount: on the Gitea runners the daemon is Docker-in-Docker and
# can't see this filesystem.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rt="${CONTAINER_RUNTIME:-docker}"
# Debian 13, as the bastion runs (debian-13 on GCE).
DEBIAN_IMAGE="${DEBIAN_IMAGE:-docker.io/library/debian:trixie-20261020-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad}"

work="$(mktemp -d)"
cid=
cleanup() { [[ -z "$cid" ]] || "$rt" rm -f "$cid" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

cp "${repo_root}/config/bastion/startup.sh" "${repo_root}/config/bastion/nftables.conf" "${repo_root}/config/bastion/ruleset.sh" \
  "${repo_root}/config/bastion/recovery.sh" "$work/"
# The attribute bootstrap.sh stops the VM on, which run.sh checks main sends.
grep -qF 'bastion_attribute settled' "${repo_root}/scripts/bootstrap.sh" || {
  echo "FAIL  bootstrap.sh doesn't wait for the settled attribute"
  exit 1
}
grep -qF 'guest-attributes/watchtower/settled' "${repo_root}/config/bastion/startup.sh" || {
  echo "FAIL  startup.sh doesn't send the settled attribute"
  exit 1
}
# Any user can put a line on the serial console, so bootstrap.sh acts on none.
if grep -q 'get-serial-port-output' "${repo_root}/scripts/bootstrap.sh"; then
  echo "FAIL  bootstrap.sh reads the serial output"
  exit 1
fi
# How bootstrap.sh reads the attributes, waits on them and changes the VM, which
# run.sh checks against what ruleset.sh sends.
: >"${work}/ruleset_state.sh"
for fn in ruleset_state login_seen guest_attribute attribute_refusal bastion_attribute bastion_boot bastion_ruleset_wait \
  bastion_login_wait bastion_update bastion_final_check bastion_on_exit bastion_stop bastion_start \
  new_nonce bastion_new_run_nonce bastion_restart_nonce bastion_up bastion_userns_word; do
  sed -n "/^${fn}() {\$/,/^}\$/p" "${repo_root}/scripts/bootstrap.sh" >>"${work}/ruleset_state.sh"
  grep -q "^${fn}() {\$" "${work}/ruleset_state.sh" || {
    echo "FAIL  bootstrap.sh has no ${fn}"
    exit 1
  }
done
# bastion_final_check has to be what comes before "Done".
last_check="$(grep -n '^bastion_final_check$' "${repo_root}/scripts/bootstrap.sh" | cut -d: -f1)"
done_line="$(grep -n '^Done\.$' "${repo_root}/scripts/bootstrap.sh" | cut -d: -f1)"
[[ -n "$last_check" && -n "$done_line" && "$last_check" -lt "$done_line" ]] || {
  echo "FAIL  bootstrap.sh can print Done without its final check"
  exit 1
}

cat >"${work}/probe.py" <<'PY'
"""serve [v6]: answers "ok" on the guard's ports, and with v6 on its IPv6
address's too. <addr> <tcp|udp> <port>: prints open, refused or timeout."""
import socket
import sys
import threading
import time

META = "169.254.169.254"
META6 = "fd20:ce::254"
TCP = [(META, 80), (META, 443), (META, 8080), (META, 53), ("127.0.0.1", 8081)]
UDP = [(META, 53), (META, 67), (META, 123), (META, 9999)]
TCP6 = [(META6, 80)]
UDP6 = [(META6, 53)]


def family(host):
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def tcp(addr):
    s = socket.socket(family(addr[0]))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(addr)
    s.listen()
    while True:
        c, _ = s.accept()
        c.sendall(b"ok")
        c.close()


def udp(addr):
    s = socket.socket(family(addr[0]), socket.SOCK_DGRAM)
    s.bind(addr)
    while True:
        _, peer = s.recvfrom(64)
        s.sendto(b"ok", peer)


if sys.argv[1] == "serve":
    v6 = sys.argv[2:] == ["v6"]
    for a in TCP + (TCP6 if v6 else []):
        threading.Thread(target=tcp, args=(a,), daemon=True).start()
    for a in UDP + (UDP6 if v6 else []):
        threading.Thread(target=udp, args=(a,), daemon=True).start()
    time.sleep(0.5)
    open("/tmp/ready", "w").close()
    while True:
        time.sleep(3600)

addr, proto, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    if proto == "tcp":
        s = socket.create_connection((addr, port), timeout=3)
    else:
        s = socket.socket(family(addr), socket.SOCK_DGRAM)
        s.settimeout(3)
        s.connect((addr, port))
        s.send(b"hi")
    print("open" if s.recv(2) == b"ok" else "closed")
except socket.timeout:
    print("timeout")
except OSError:
    print("refused")
PY

cat >"${work}/run.sh" <<'RUN'
set -euo pipefail
cd /check
# The probes run as other uids too.
chmod 0755 /check
chmod 0644 /check/*
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
# systemd and openssh-server for their units: neither runs here.
# duktape for polkit's rule, under the engine polkit itself uses here.
apt-get install -y -qq --no-install-recommends nftables python3 iproute2 systemd openssh-server cron duktape >/dev/null

fail=0
pass() { echo "ok    $*"; }
flunk() { echo "FAIL  $*"; fail=1; }

# --- peer: startup.sh's check_peer -------------------------------------------
BASTION_STARTUP_LIB=1 . ./startup.sh
set +e
mkdir -p peers
# peer_case <name> <accept|refuse> <config on stdin>; an accepted one's
# normalised config must equal peers/<name>.want when there is one.
peer_case() {
  local name=$1 expect=$2 got
  cat >"peers/${name}.in"
  if check_peer "peers/${name}.in" "peers/${name}.out" 2>"peers/${name}.err"; then got=accept; else got=refuse; fi
  if [[ "$got" != "$expect" ]]; then
    flunk "peer ${name}: ${got%e}ed, want it ${expect%e}ed"
  elif grep -q LEAKCHECK "peers/${name}.err"; then
    flunk "peer ${name}: the refusal echoes the config"
  elif [[ -f "peers/${name}.want" ]] && ! diff -u "peers/${name}.want" "peers/${name}.out"; then
    flunk "peer ${name}: normalised wrong"
  elif [[ "$got" == refuse ]]; then
    pass "peer ${name}: refused ($(head -1 "peers/${name}.err"))"
  else
    pass "peer ${name}: accepted"
  fi
}

# A dummy in a real key's shape: all zeros.
key="$(printf 'A%.0s' {1..43})="

# What wg-easy publishes for an agent (roles/edge/tasks/peer.yml pins it):
# taken as it is.
cat >peers/wg-easy.want <<EOF
[Interface]
PrivateKey = ${key}
Address = 10.8.0.129/32
MTU = 1380
[Peer]
PublicKey = ${key}
PresharedKey = ${key}
AllowedIPs = 10.8.0.0/24
PersistentKeepalive = 25
Endpoint = vpn.watchtower.jasonmross.dev:51820
EOF
peer_case wg-easy accept <<EOF
[Interface]
PrivateKey = ${key}
Address = 10.8.0.129/32
MTU = 1380

[Peer]
PublicKey = ${key}
PresharedKey = ${key}
AllowedIPs = 10.8.0.0/24
PersistentKeepalive = 25
Endpoint = vpn.watchtower.jasonmross.dev:51820
EOF

# No MTU or keepalive, a DNS line, comments, CRLF and odd case and spacing:
# normalised.
cat >peers/normalised.want <<EOF
[Interface]
MTU = 1380
PrivateKey = ${key}
Address = 10.8.0.129/32
[Peer]
PersistentKeepalive = 25
PublicKey = ${key}
AllowedIPs = 10.8.0.0/24
Endpoint = 192.0.2.1:51820
EOF
peer_case normalised accept <<EOF
# made by wg-easy
[interface]
privatekey=${key}
  Address = 10.8.0.129/32   # the agent half
dns = 1.1.1.1
[PEER]
PublicKey = ${key}
allowedips = 10.8.0.0/24
Endpoint = 192.0.2.1:51820
EOF
sed 's/$/\r/' peers/normalised.in >peers/crlf.in
if check_peer peers/crlf.in peers/crlf.out 2>/dev/null && diff -q peers/normalised.want peers/crlf.out >/dev/null; then
  pass "peer crlf: accepted"
else
  flunk "peer crlf: not normalised"
fi

good_interface="[Interface]
PrivateKey = ${key}
Address = 10.8.0.129/32"
good_peer="[Peer]
PublicKey = ${key}
AllowedIPs = 10.8.0.0/24
Endpoint = 192.0.2.1:51820"
for hook in PreUp PostUp PreDown PostDown; do
  printf '%s\n%s = touch /tmp/LEAKCHECK\n%s\n' "$good_interface" "$hook" "$good_peer" | peer_case "$hook" refuse
done
printf '%s\n  postup=touch /tmp/LEAKCHECK\n%s\n' "$good_interface" "$good_peer" | peer_case postup-lowercase refuse
printf '%s\nTable = off\n%s\n' "$good_interface" "$good_peer" | peer_case table refuse
printf '%s\nFwMark = 0xca6c\n%s\n' "$good_interface" "$good_peer" | peer_case fwmark refuse
printf '%s\nSaveConfig = true\n%s\n' "$good_interface" "$good_peer" | peer_case saveconfig refuse
printf '%s\n%s\n' "$good_interface" "${good_peer/10.8.0.0\/24/0.0.0.0/0}" | peer_case full-tunnel refuse
printf '%s\n%s\n' "$good_interface" "${good_peer/10.8.0.0\/24/10.8.0.0/24, 10.9.0.0/16 # LEAKCHECK}" | peer_case more-routes refuse
printf '%s\n%s\nAllowedIPs = 169.254.169.254/32\n' "$good_interface" "$good_peer" | peer_case second-allowedips refuse
printf '%s\n%s\n%s\n' "$good_interface" "$good_peer" "$good_peer" | peer_case two-peers refuse
printf '%s\n' "$good_interface" | peer_case no-peer refuse
printf '%s\n%s\n' "$good_interface" "${good_peer/Endpoint = 192.0.2.1:51820/}" | peer_case no-endpoint refuse
printf '%s\n' "$good_peer" | peer_case no-interface refuse
printf '%s\nEndpoint = 192.0.2.1:51820\n%s\n' "$good_interface" "$good_peer" | peer_case endpoint-in-interface refuse
printf 'MTU = 1380\n%s\n%s\n' "$good_interface" "$good_peer" | peer_case before-a-section refuse
printf '%s\n%s\n[Extra]\nLEAKCHECK = 1\n' "$good_interface" "$good_peer" | peer_case unknown-section refuse
printf '%s\n%s\nLEAKCHECK\n' "$good_interface" "$good_peer" | peer_case not-key-value refuse
printf '' | peer_case empty refuse

# wg deletes all whitespace from a line, and wg-quick trims any: what either
# would run or route must not get past as some other key.
i=0
for shape in 'PreUp\f' 'PreUp\v' 'PreUp\r' 'Pre Up' 'Post\tUp' 'PostUp\xe2\x80\x83' '\xe2\x80\x83PostUp' 'PostUp\xc2\xa0'; do
  i=$((i + 1))
  printf "%s\n${shape} = touch /tmp/LEAKCHECK\n%s\n" "$good_interface" "$good_peer" | peer_case "spaced-hook-${i}" refuse
done
for shape in 'Table\f = off' 'SaveConfig\f = true' 'Fw Mark = 51820' 'Save Config = true' 'ListenPort = 51820'; do
  i=$((i + 1))
  printf "%s\n${shape}\n%s\n" "$good_interface" "$good_peer" | peer_case "spaced-interface-${i}" refuse
done
for shape in 'Allowed IPs = 0.0.0.0/0' 'AllowedIPs\f = 0.0.0.0/0' 'Allowed\tIPs = 169.254.169.254/32'; do
  i=$((i + 1))
  printf "%s\n[Peer]\nPublicKey = %s\n${shape}\nEndpoint = 192.0.2.1:51820\n" "$good_interface" "$key" | peer_case "spaced-route-${i}" refuse
done
# ... or be left for wg to echo: a key it can't read, or under another name.
for bad in dummy-private-key-LEAKCHECK "${key%?}LEAKCHECK=" "${key:1}" "${key%?}"; do
  i=$((i + 1))
  printf '%s\n%s\n' "${good_interface/${key}/${bad}}" "$good_peer" | peer_case "bad-private-key-${i}" refuse
done
printf '%s\n%s\n' "$good_interface" "${good_peer/${key}/dummy-public-key-LEAKCHECK}" | peer_case bad-public-key refuse
printf '%s\n%s\nPresharedKey = dummy-preshared-key-LEAKCHECK\n' "$good_interface" "$good_peer" | peer_case bad-preshared-key refuse
printf '[Interface]\nPrivKey = dummy-private-key-LEAKCHECK\nAddress = 10.8.0.129/32\n%s\n' "$good_peer" | peer_case misnamed-key refuse
printf '%s\nLEAKCHECK = 1\n%s\n' "$good_interface" "$good_peer" | peer_case unknown-setting refuse
printf '%s\nPublicKey = %s\n%s\n' "$good_interface" "$key" "$good_peer" | peer_case key-in-the-wrong-section refuse
printf '%s\nPrivateKey = %s\n%s\n' "$good_interface" "$key" "$good_peer" | peer_case two-private-keys refuse
printf '%s\n%s\nEndpoint = 192.0.2.2:51820\n' "$good_interface" "$good_peer" | peer_case two-endpoints refuse
printf '[Interface]\nAddress = 10.8.0.129/32\n%s\n' "$good_peer" | peer_case no-private-key refuse
printf '[Interface]\nPrivateKey = %s\nAddress = 169.254.169.254/32\n%s\n' "$key" "$good_peer" | peer_case address-off-the-tunnel refuse
printf '[Interface]\nPrivateKey = %s\nAddress = 10.8.0.129/24\n%s\n' "$key" "$good_peer" | peer_case address-a-whole-network refuse
printf '%s\nMTU = LEAKCHECK\n%s\n' "$good_interface" "$good_peer" | peer_case bad-mtu refuse
printf '%s\n%s\nPersistentKeepalive = LEAKCHECK\n' "$good_interface" "$good_peer" | peer_case bad-keepalive refuse
printf '%s\n%s\n' "$good_interface" "${good_peer/192.0.2.1:51820/LEAKCHECK}" | peer_case bad-endpoint refuse
# Whitespace wg deletes in a setting that is fine: written out clean.
printf '[Interface]\nPrivateKey = %s\nAdd\fress =\t10.8.0. 129/32\n%s\n' "$key" "$good_peer" | peer_case spaced-address accept
if grep -qx 'Address = 10.8.0.129/32' peers/spaced-address.out; then pass "peer spaced-address: written out clean"; else flunk "peer spaced-address: not written out clean"; fi

# --- apt: what a stop leaves, and what bootstrap.sh waits for ------------------
# An unreplayed entry in dpkg's journal, which is what an install killed in
# the middle of its unpacking leaves.
touch /var/lib/dpkg/updates/0000
if apt_get install -y jq >/dev/null 2>&1; then
  flunk "apt: apt_get took an interrupted dpkg; the next check shows nothing"
else
  pass "apt: an interrupted dpkg stops apt_get"
fi
if apt_install --no-install-recommends jq >/dev/null 2>&1 && installed jq; then
  pass "apt: apt_install heals it and installs"
else
  flunk "apt: apt_install didn't heal an interrupted dpkg"
fi
if installed jq no-such-package; then flunk "apt: installed says yes to a missing package"; else pass "apt: installed says no to a missing package"; fi

# main, with everything that touches the system stubbed: the order is the test.
main_order="$(
  userns_off() { echo userns; }
  updates() { echo updates; }
  guard() { echo guard; }
  guard_loaded() { return 0; }
  installed() { return 1; }
  apt_install() { echo apt; }
  fetch_peer() { peer_state=none; }
  teardown() { echo teardown; }
  ping_setup() { :; }
  ping_if_up() { echo ping; }
  report_tool() { echo tool; }
  report_userns() { echo userns-said; }
  # The attribute's PUT, which comes with the line.
  curl() { [[ "$*" == *guest-attributes/watchtower/settled* ]] && echo settled-attribute; }
  main 2>/dev/null | tr '\n' ' '
)"
if [[ "$main_order" == "userns guard tool userns-said bastion: metadata guard loaded updates apt bastion: settled settled-attribute ping teardown " ]]; then
  pass "apt: main turns user namespaces off before anything else, says settled only after the guard and apt, the guard goes next and then which tool it ran and the user namespaces, and the ping comes before anything of telemetry"
else
  flunk "apt: main's order is: ${main_order}"
fi

# --- nonce: startup.sh's side of the run nonce ---------------------------------
# keep_run_nonce keeps metadata's value for root alone, and only one of its shape; the
# settled and tool attributes carry it, and "-" when there is none.
# nonce_case <name> <what metadata says, or "none"> <want: kept or none>
nonce_case() {
  local name=$1 says=$2 want=$3 dir got
  dir="$(mktemp -d)"
  got="$(
    RUN_NONCE="${dir}/nonce"
    mds() { [[ "$says" != none && "$1" == instance/attributes/watchtower-run-nonce ]] && printf '%s' "$says"; }
    keep_run_nonce 2>/dev/null
    if [[ -f "$RUN_NONCE" ]]; then
      echo "file $(stat -c '%a %U' "$RUN_NONCE")"
    fi
    echo "says $(run_nonce)"
  )"
  local ok=""
  case "$want" in
    kept) [[ "$got" != "file 600 root"*"says ${says}" ]] || ok=1 ;;
    none) [[ "$got" != "says -" ]] || ok=1 ;;
  esac
  if [[ -n "$ok" ]]; then pass "nonce ${name}: ${want}"; else flunk "nonce ${name}: ${got//$'\n'/ }"; fi
}
# Under a umask that would leave it readable to all: keep_run_nonce makes it 0600 itself.
umask_before="$(umask)"
umask 022
nonce_case "one of its shape" "$(printf '%032x' 7)" kept
nonce_case "none in metadata" none none
nonce_case "not hex" "$(printf 'z%.0s' {1..32})" none
nonce_case "too short" "$(printf '%031x' 7)" none
nonce_case "a value that would add to the attribute" "$(printf '%032x' 7) boot x" none
# A file there already, readable to all: not written into, so not left readable.
nonce_left="$(
  RUN_NONCE="$(mktemp)"
  chmod 0644 "$RUN_NONCE"
  mds() { printf '%032x' 8; }
  keep_run_nonce 2>/dev/null
  stat -c '%a %U' "$RUN_NONCE"
)"
if [[ "$nonce_left" == "600 root" ]]; then pass "nonce: one readable to all from before is replaced, 0600"; else flunk "nonce: left as ${nonce_left}"; fi
umask "$umask_before"
# What the settled, tool and userns attributes are sent: <boot id> [<sha256>] and the
# run nonce.
# report_tool keeps its word for a login to say again: here, under a umask that would
# leave it readable to all.
tool_word_dir="$(mktemp -d)"
attribute_sent="$(
  RUN_NONCE="$(mktemp)"
  printf '%032x\n' 7 >"$RUN_NONCE"
  RULESET_TOOL="$(mktemp)"
  echo a-tool >"$RULESET_TOOL"
  TOOL_WORD="${tool_word_dir}/tool"
  curl() { local a; for a in "$@"; do [[ "$a" != *" run "* ]] || echo "${*: -1} ${a}"; done; }
  report_settled
  umask 022
  report_tool
  userns_state=off
  report_userns
  userns_state=""
  report_userns
)"
if grep -qxF "http://169.254.169.254/computeMetadata/v1/instance/guest-attributes/watchtower/userns off boot $(cat /proc/sys/kernel/random/boot_id) run $(printf '%032x' 7)" <<<"$attribute_sent"; then
  pass "nonce: userns carries off, the boot and its run nonce"
else
  flunk "nonce: userns was sent: ${attribute_sent}"
fi
if grep -qxF "http://169.254.169.254/computeMetadata/v1/instance/guest-attributes/watchtower/userns on boot $(cat /proc/sys/kernel/random/boot_id) run $(printf '%032x' 7)" <<<"$attribute_sent"; then
  pass "nonce: userns, not known to be off, says on"
else
  flunk "nonce: userns, not known to be off, was sent: ${attribute_sent}"
fi
this_boot_now="$(cat /proc/sys/kernel/random/boot_id)"
tool_sum="$(echo a-tool | sha256sum | cut -d' ' -f1)"
if grep -qxF "http://169.254.169.254/computeMetadata/v1/instance/guest-attributes/watchtower/settled ${this_boot_now} run $(printf '%032x' 7)" <<<"$attribute_sent"; then
  pass "nonce: settled carries the boot and its run nonce"
else
  flunk "nonce: settled was sent: ${attribute_sent}"
fi
if grep -qxF "http://169.254.169.254/computeMetadata/v1/instance/guest-attributes/watchtower/tool ${tool_sum} boot ${this_boot_now} run $(printf '%032x' 7)" <<<"$attribute_sent"; then
  pass "nonce: tool carries the tool's sha256, the boot and its run nonce"
else
  flunk "nonce: tool was sent: ${attribute_sent}"
fi
if [[ "$(cat "${tool_word_dir}/tool" 2>/dev/null)" == "${tool_sum} boot ${this_boot_now} run $(printf '%032x' 7)" ]]; then
  pass "nonce: report_tool keeps that word for a login to say again"
else
  flunk "nonce: report_tool kept: $(cat "${tool_word_dir}/tool" 2>&1)"
fi
if [[ "$(stat -c '%a %U' "${tool_word_dir}/tool" 2>/dev/null)" == "600 root" ]]; then pass "nonce: the kept tool word is root's, 0600"; else flunk "nonce: the kept tool word is $(stat -c '%a %U' "${tool_word_dir}/tool" 2>&1)"; fi

# --- userns: unprivileged user namespaces off ---------------------------------
# This container runs the host's kernel, not Debian's, so it has no such knob: a file
# stands in for it, and sysctl for what the kernel does with the setting. Only the VM
# shows the real knob at 0 and a user's `unshare --user` refused.
# userns_case <name> <the knob's answer: takes, absent or refuses> <want: off or warned>
userns_case() {
  local name=$1 knob=$2 want=$3 dir out rc
  dir="$(mktemp -d)"
  out="$(
    USERNS_CONF="${dir}/90-watchtower-userns.conf"
    USERNS_KNOB="${dir}/knob"
    work="$(mktemp -d)"
    [[ "$knob" == absent ]] || echo 1 >"$USERNS_KNOB"
    sysctl() {
      echo "sysctl $*" >>"${dir}/calls"
      [[ "$knob" == takes ]] || return 255
      # The kernel takes what the file says.
      sed -n 's/^kernel\.unprivileged_userns_clone = \([0-9]\)$/\1/p' "$3" >"$USERNS_KNOB"
    }
    userns_state=""
    userns_off 2>&1
    echo "state ${userns_state}"
  )"
  rc=$?
  if [[ "$rc" != 0 ]]; then
    flunk "userns ${name}: returned ${rc}"
  elif [[ "$want" == off && ("$out" != *"unprivileged user namespaces: off"* || "$out" != *"state off") ]]; then
    flunk "userns ${name}: doesn't say they're off: ${out}"
  elif [[ "$want" == warned && ("$out" != *"warning: unprivileged user namespaces may be on"* || "$out" != *"state on") ]]; then
    flunk "userns ${name}: doesn't warn, or keep it as on: ${out}"
  else
    pass "userns ${name}: ${want}, and returns 0"
  fi
  userns_file="${dir}/90-watchtower-userns.conf"
  userns_calls="$(cat "${dir}/calls" 2>/dev/null)"
}
userns_case "the knob takes it" takes off
# The setting itself, for good: Debian's knob at 0, and nothing that stops root too.
if [[ "$(grep -v '^#' "$userns_file")" == "kernel.unprivileged_userns_clone = 0" ]]; then
  pass "userns: the file sets kernel.unprivileged_userns_clone = 0, and nothing else"
else
  flunk "userns: the file holds: $(cat "$userns_file" 2>/dev/null)"
fi
if [[ "$(stat -c '%a %U' "$userns_file")" == "644 root" ]]; then pass "userns: the file is root's, 0644"; else flunk "userns: the file is $(stat -c '%a %U' "$userns_file")"; fi
if [[ "$userns_calls" == "sysctl -q -p ${userns_file}" ]]; then pass "userns: applied now, from that file"; else flunk "userns: sysctl was asked: ${userns_calls}"; fi
userns_case "a kernel without the knob" absent warned
userns_case "a kernel that refuses it" refuses warned

# --- fetch: only a missing or empty secret takes telemetry down ----------------
# fetch_case <name> <want> <email code> <token code> <secret code> <body>
fetch_case() {
  local name=$1 want=$2 email=$3 token=$4 secret=$5 body=$6 got
  got="$(
    work="$(mktemp -d)"
    get() {
      case "$1" in
        */email) echo "$email" ;;
        */token) echo '{"access_token":"x"}' >"$2"; echo "$token" ;;
        *:access) cat >/dev/null; printf '%s' "$body" >"$2"; echo "$secret" ;;
      esac
    }
    fetch_peer "${work}/peer.in" 2>/dev/null
    echo "$peer_state"
  )"
  if [[ "$got" == "$want" ]]; then pass "fetch ${name}: ${got}"; else flunk "fetch ${name}: ${got}, want ${want}"; fi
}
peer_b64="$(printf '[Interface]\n' | base64 -w0)"
fetch_case a-peer have 200 200 200 "{\"payload\":{\"data\":\"${peer_b64}\"}}"
fetch_case no-version none 200 200 404 '{"error":{"code":404}}'
fetch_case empty-version none 200 200 200 '{"payload":{}}'
fetch_case permission-denied unknown 200 200 403 '{"error":{"code":403}}'
fetch_case server-error unknown 200 200 503 ''
fetch_case no-answer unknown 200 200 000 ''
fetch_case malformed unknown 200 200 200 'not json'
fetch_case no-token unknown 200 500 200 ''
fetch_case metadata-down unknown 000 200 200 ''
fetch_case no-account unknown 404 200 200 ''

# main_case <name> <want teardown or not> <exit status> <peer_state>: a config
# in peer.in that fails the checks.
main_case() {
  local name=$1 want=$2 want_rc=$3 state=$4 got rc
  got="$(
    updates() { :; }
    guard() { :; }
    guard_loaded() { return 0; }
    installed() { return 0; }
    fetch_peer() { peer_state="$state"; printf 'not a config\n' >"$1"; }
    teardown() { echo teardown; }
    health() { :; }
    report_settled() { :; }
    ping_setup() { :; }
    ping_if_up() { :; }
    main 2>/dev/null
  )"
  rc=$?
  if [[ "$rc" == "$want_rc" && "$got" == *teardown* && "$want" == teardown ]] || [[ "$rc" == "$want_rc" && "$got" != *teardown* && "$want" == keep ]]; then
    pass "fetch main ${name}: ${want}, exit ${rc}"
  else
    flunk "fetch main ${name}: exit ${rc} and ${got//$'\n'/ }, want ${want} and exit ${want_rc}"
  fi
}
main_case a-missing-secret teardown 0 none
main_case any-other-failure keep 0 unknown
main_case a-config-that-fails-its-checks keep 1 have

# guard_case <name> <the tool's exit status> <the attribute's answer: yes or no>
# <want the script's exit status> <want the tool's arguments>: startup.sh's side
# of ruleset.sh. Metadata's ruleset tool never answers: the one on disk stays.
guard_case() {
  local name=$1 tool_rc=$2 attribute=$3 want_rc=$4 want_args=$5 got rc
  got="$(
    work="$(mktemp -d)"
    RULESET_TOOL="${work}/tool"
    # None, so a failure stands: the last good copy has its own cases (tool, below).
    TOOL_LAST_GOOD="${work}/last-good"
    # Whole, as the real tool is: it ends with main "$@".
    cat >"$RULESET_TOOL" <<TOOL
#!/bin/bash
main() {
  [[ "\$1" == setup ]] && exit 0
  shift
  echo "args \${#}"
  exit ${tool_rc}
}
main "\$@"
TOOL
    chmod 0755 "$RULESET_TOOL"
    installed() { return 0; }
    mds() {
      case "$1" in
        */watchtower-nftables-retry) [[ "$attribute" == yes ]] && echo 7 ;;
        *) return 22 ;;
      esac
    }
    mds_file() {
      case "$1" in
        */watchtower-nftables) [[ "$attribute" == yes ]] && echo ruleset >"$2" ;;
        *) return 22 ;;
      esac
    }
    guard 2>/dev/null
    echo "after"
  )"
  rc=$?
  if [[ "$rc" == "$want_rc" && "$got" == *"args ${want_args}"* ]]; then
    pass "fetch guard ${name}: exit ${rc}, ${want_args} args"
  else
    flunk "fetch guard ${name}: exit ${rc}, ${got//$'\n'/ }; want exit ${want_rc}, ${want_args} args"
  fi
}
guard_case metadata-answers 0 yes 0 2
guard_case metadata-silent-keeps-what-is-on-disk 0 no 0 0
guard_case a-rollback-stops-the-script 75 yes 0 2
guard_case sshd-may-not-run-stops-the-script 1 yes 1 2

# A retry on stdout leaves a stalled try's part in front of the whole: a named file.
mds_file_args="$(curl() { printf '%s' "$*"; }; mds_file instance/attributes/a-file /tmp/a-file)"
if [[ "$mds_file_args" == *"-o /tmp/a-file"* && "$mds_file_args" == *"/instance/attributes/a-file" ]]; then
  pass "fetch mds_file: into a file by name"
else
  flunk "fetch mds_file: curl was asked: ${mds_file_args}"
fi
for attribute_file in watchtower-ruleset watchtower-nftables watchtower-alloy; do
  if grep -qE "mds_file instance/attributes/${attribute_file} " startup.sh; then
    pass "fetch ${attribute_file}: into a file by name"
  else
    flunk "fetch ${attribute_file}: not into a file by name"
  fi
done

# teardown takes the temp file a reset in the middle of put leaves, which holds the key.
teardown_dir="$(mktemp -d)"
touch "${teardown_dir}/wg.conf" "${teardown_dir}/wg.conf.tmp" "${teardown_dir}/alloy"
(
  WG_CONF="${teardown_dir}/wg.conf"
  ALLOY_CONFIG="${teardown_dir}/alloy"
  systemctl() { return 1; }
  teardown
)
if [[ -z "$(find "$teardown_dir" -mindepth 1 -print -quit)" ]]; then
  pass "fetch teardown: takes the config, its temp file and Alloy's"
else
  flunk "fetch teardown: leaves: $(ls "$teardown_dir")"
fi

# --- ping: startup.sh's ping of its Healthchecks.io check ------------------------
# A stand-in, the shape of a real one and nothing else's.
ping_stand_in='https://hc-ping.com/stand-in-for-the-ping-url'
ping_b64="$(printf '%s' "$ping_stand_in" | base64 -w0)"
# ping_case <name> <pinged, failed or none> <guard up or down> <sshd up or down>
# <token code> <secret code> <the secret's body> [curl's exit status]. Whatever
# comes of it, it must return 0 and hold the URL back from everything but curl's
# stdin. curl's own words hold it here too, as they might.
ping_case() {
  local name=$1 want=$2 guard_state=$3 sshd_state=$4 token=$5 secret=$6 body=$7 curl_rc=${8:-0} out rc got=none
  rm -f /tmp/ping-args /tmp/ping-stdin
  out="$(
    work="$(mktemp -d)"
    guard_loaded() { [[ "$guard_state" == up ]]; }
    guard_refuses_users() { [[ "$guard_state" == up ]]; }
    systemctl() { [[ "$*" == "is-active --quiet ssh.service" && "$sshd_state" == up ]]; }
    get() {
      case "$1" in
        */token) echo '{"access_token":"x"}' >"$2"; echo "$token" ;;
        *healthchecks-bastion-url/versions/latest:access) cat >/dev/null; printf '%s' "$body" >"$2"; echo "$secret" ;;
      esac
    }
    curl() {
      printf '%s' "$*" >/tmp/ping-args
      cat >/tmp/ping-stdin
      echo "curl: (22) ${ping_stand_in} said no" >&2
      return "$curl_rc"
    }
    ping_if_up 2>&1
  )"
  rc=$?
  if [[ -e /tmp/ping-stdin ]]; then
    if grep -q 'pinged the Healthchecks.io check' <<<"$out"; then got=pinged; else got=failed; fi
  fi
  if [[ "$got" != "$want" || "$rc" != 0 ]]; then
    flunk "ping ${name}: ${got}, return ${rc}; want ${want}, return 0"
  elif [[ "$out" == *stand-in-for* ]]; then
    flunk "ping ${name}: the URL is in its output"
  elif [[ -e /tmp/ping-args && "$(cat /tmp/ping-args)" == *stand-in-for* ]]; then
    flunk "ping ${name}: the URL is in curl's arguments"
  elif [[ "$got" != none && "$(cat /tmp/ping-stdin)" != "url = \"${ping_stand_in}\"" ]]; then
    flunk "ping ${name}: curl's stdin isn't the URL alone"
  elif [[ "$got" != none && "$(cat /tmp/ping-args)" != *"-K -"* ]]; then
    flunk "ping ${name}: curl doesn't read its config from stdin"
  elif [[ -z "$out" ]]; then
    flunk "ping ${name}: says nothing"
  else
    pass "ping ${name}: ${got}"
  fi
}
ping_ok="{\"payload\":{\"data\":\"${ping_b64}\"}}"
ping_case all-up pinged up up 200 200 "$ping_ok"
ping_case no-guard none down up 200 200 "$ping_ok"
ping_case no-sshd none up down 200 200 "$ping_ok"
ping_case neither none down down 200 200 "$ping_ok"
ping_case no-account none up up 404 200 "$ping_ok"
ping_case no-token none up up 500 200 "$ping_ok"
ping_case metadata-down none up up 000 200 "$ping_ok"
ping_case no-secret-version none up up 200 404 '{"error":{"code":404}}'
ping_case permission-denied none up up 200 403 '{"error":{"code":403}}'
ping_case secret-manager-down none up up 200 000 ''
ping_case empty-secret none up up 200 200 '{"payload":{}}'
ping_case malformed-answer none up up 200 200 'not json'
ping_case not-base64 none up up 200 200 '{"payload":{"data":"!!!"}}'
ping_case another-host none up up 200 200 "{\"payload\":{\"data\":\"$(printf 'https://example.com/stand-in-for' | base64 -w0)\"}}"
ping_case plain-http none up up 200 200 "{\"payload\":{\"data\":\"$(printf 'http://hc-ping.com/stand-in-for' | base64 -w0)\"}}"
ping_case a-value-adding-to-curls-config none up up 200 200 "{\"payload\":{\"data\":\"$(printf 'https://hc-ping.com/x"\noutput = "/etc/stand-in-for' | base64 -w0)\"}}"
ping_case ping-fails failed up up 200 200 "$ping_ok" 22
ping_case ping-times-out failed up up 200 200 "$ping_ok" 28

# No failure stops the boot, and the timer's way in does the ping and nothing else.
ping_main="$(
  updates() { :; }
  guard() { echo guard; }
  guard_loaded() { return 0; }
  guard_refuses_users() { return 0; }
  installed() { return 0; }
  report_settled() { :; }
  systemctl() { [[ "$1" == is-active ]]; }
  # Nothing answers, and put dies, as it does on a full disk.
  get() { echo 000; }
  put() { die "no room"; }
  fetch_peer() { peer_state=none; }
  teardown() { echo teardown; }
  main 2>&1
  echo "main returned $?"
)"
if grep -qx teardown <<<"$ping_main" && grep -qx 'main returned 0' <<<"$ping_main"; then
  pass "ping: the daily ping's setup and a ping that fail stop nothing else"
else
  flunk "ping: a failure stopped the boot: ${ping_main//$'\n'/ }"
fi
for said in 'could not set up the daily ping' 'could not ping the Healthchecks.io check'; do
  if grep -qF "$said" <<<"$ping_main"; then pass "ping: says \"${said}\""; else flunk "ping: doesn't say \"${said}\""; fi
done
ping_only="$(
  guard() { echo guard; }
  updates() { echo updates; }
  fetch_peer() { echo fetch; }
  ping_if_up() { echo ping; }
  main ping 2>&1 | tr '\n' ' '
)"
if [[ "$ping_only" == "ping " ]]; then pass "ping: main ping does the ping alone"; else flunk "ping: main ping does: ${ping_only}"; fi
set -e

# --- guard: nftables.conf ----------------------------------------------------
ip addr add 169.254.169.254/32 dev lo
# Its IPv6 address too, where the container has IPv6 (Docker's may not).
v6=""
ip -6 addr add fd20:ce::254/128 dev lo nodad 2>/dev/null && v6=v6
nft --check --file nftables.conf
pass "guard: nft --check"
nft --file nftables.conf
nft --file nftables.conf
if [[ "$(nft list tables | grep -c 'metadata_guard')" == 1 ]]; then
  pass "guard: loads, and reloads in place"
else
  flunk "guard: not exactly one metadata_guard table after a reload"
fi
python3 probe.py serve "$v6" &
for _ in $(seq 50); do [[ -e /tmp/ready ]] && break; sleep 0.1; done

# probe <uid> <addr> <proto> <port> <want>
probe() {
  local got
  got="$(setpriv --reuid="$1" --regid="$1" --clear-groups python3 probe.py "$2" "$3" "$4")"
  if [[ "$got" == "$5" ]]; then pass "guard: uid $1 -> $2 $3/$4: ${got}"; else flunk "guard: uid $1 -> $2 $3/$4: ${got}, want $5"; fi
}
meta=169.254.169.254
probe 0 "$meta" tcp 80 open
probe 0 "$meta" tcp 443 open
for uid in 65534 1000; do
  probe "$uid" "$meta" tcp 80 refused
done
probe 65534 "$meta" tcp 443 refused
probe 65534 "$meta" tcp 8080 refused
probe 65534 "$meta" udp 9999 refused
probe 65534 "$meta" udp 53 open
probe 65534 "$meta" tcp 53 open
probe 65534 "$meta" udp 67 open
probe 65534 "$meta" udp 123 open
probe 65534 127.0.0.1 tcp 8081 open
if [[ -n "$v6" ]]; then
  probe 0 fd20:ce::254 tcp 80 open
  probe 65534 fd20:ce::254 tcp 80 refused
  probe 65534 fd20:ce::254 udp 53 open
else
  echo "skip  guard: no IPv6 here, so fd20:ce::254 is only nft --check'ed"
fi
# Not piped: grep -q stops reading at its match, and pipefail then takes nft's
# failed write for a failed check.
guard_chain="$(nft list chain inet metadata_guard metadata)"
if grep -Eq 'counter packets [1-9]' <<<"$guard_chain"; then
  pass "guard: refusals counted"
else
  flunk "guard: no refusal counted"
fi

# --- ruleset: ruleset.sh's dead man's switch -----------------------------------
set +e
. ./ruleset_state.sh
state_dir=/var/lib/watchtower-bastion
dropbox=/run/watchtower-ruleset
timer=watchtower-ruleset-rollback.timer
stubs=/stubs
mkdir -p "$stubs"
chmod 0755 "$stubs"
# systemctl records what it's asked, and "loads" as the unit does; a flag file
# breaks the load or the timer. curl is the metadata server's answer on a VM's
# account.
cat >"${stubs}/systemctl" <<'STUB'
#!/bin/bash
echo "$*" >>/stubs/calls
case "$*" in
  "reload-or-restart nftables.service")
    # What a flag makes happen at the moment of the load.
    [[ ! -e /stubs/at-load-disk-fails ]] || touch /stubs/install-broken
    [[ ! -e /stubs/at-load-a-login ]] || touch /run/watchtower-ruleset/an-early-login
    [[ ! -e /stubs/load-broken ]] && nft --file "$(cat /stubs/ruleset-path 2>/dev/null || echo /etc/nftables.conf)" 2>/dev/null ;;
  "restart watchtower-ruleset-rollback.timer")
    [[ ! -e /stubs/timer-broken ]] ;;
  "is-active --quiet ssh.service")
    [[ ! -e /stubs/sshd-down ]] ;;
  "start ssh.service")
    # sshd that won't start whatever the gate says, as a bad config does.
    [[ ! -e /stubs/sshd-start-broken ]] || exit 1
    # sshd with no gate at all, as with its drop-in gone: any start gets it up.
    [[ ! -e /stubs/sshd-ungated ]] || rm -f /stubs/sshd-down
    # sshd as it really is: nothing without its ExecStartPre, which is the tool.
    if [[ -e /stubs/sshd-runs-its-gate ]]; then
      if /usr/local/sbin/watchtower-ruleset gate >/dev/null 2>&1; then
        rm -f /stubs/sshd-down
      else
        touch /stubs/sshd-down
        exit 1
      fi
    fi ;;
  "stop ssh.service")
    [[ ! -e /stubs/sshd-runs-its-gate && ! -e /stubs/sshd-ungated ]] || touch /stubs/sshd-down ;;
esac
STUB
cat >"${stubs}/curl" <<'STUB'
#!/bin/bash
# In a network namespace with nothing but lo, as a self-check's is, the metadata server
# is out of reach, as on the VM: nothing answers.
if [[ -z "$(ip -o link show 2>/dev/null | grep -v ': lo:')" ]]; then
  printf '000'
  exit 7
fi
args=("$@")
for ((i = 0; i < $#; i++)); do
  if [[ "${args[i]}" == --data ]]; then
    [[ ! -e /stubs/attribute-broken ]] || exit 7
    # The ruleset's in /stubs/attribute, the others in a file of their own.
    url="${!#}"
    case "$url" in
      */watchtower/ruleset) printf '%s\n' "${args[i + 1]}" >/stubs/attribute ;;
      *) printf '%s\n' "${args[i + 1]}" >"/stubs/attribute-${url##*/}" ;;
    esac
    exit 0
  fi
done
cat /stubs/account-code
STUB
# A disk that won't take the ruleset: what ENOSPC or a read-only root does to it.
cat >"${stubs}/install" <<'STUB'
#!/bin/bash
[[ -e /stubs/install-broken && "$*" == *"/etc/nftables.conf.tmp"* ]] && exit 1
exec /usr/bin/install "$@"
STUB
# nft that loads nothing at all, not even the floor.
cat >"${stubs}/nft" <<'STUB'
#!/bin/bash
[[ -e /stubs/nft-broken && "$1" != list ]] && exit 1
exec /usr/sbin/nft "$@"
STUB
chmod 0755 "${stubs}/systemctl" "${stubs}/curl" "${stubs}/install" "${stubs}/nft"

tool() { PATH="${stubs}:${PATH}" bash /check/ruleset.sh "$@"; }
as_user() { setpriv --reuid=65534 --regid=65534 --clear-groups env PATH="${stubs}:${PATH}" "$@"; }
# Gone, or dead with only its parent left to notice.
proc_gone() { [[ ! -d "/proc/$1" || "$(cut -d' ' -f3 "/proc/$1/stat" 2>/dev/null)" == Z ]]; }
guard_on() { nft list chain inet metadata_guard metadata >/dev/null 2>&1; }
called() { grep -qxF -- "$1" "${stubs}/calls"; }
# check <name> <command...>
check() {
  local name=$1
  shift
  if "$@"; then pass "ruleset: ${name}"; else flunk "ruleset: ${name}"; fi
}
refute() {
  local name=$1
  shift
  if "$@"; then flunk "ruleset: ${name}"; else pass "ruleset: ${name}"; fi
}
same_file() { cmp -s "$1" "$2"; }
no_file() { [[ ! -e "$1" ]]; }
# What the last command told the guest attribute, as bootstrap.sh reads it.
state_is() { [[ "$(ruleset_state "$1" "" <"${stubs}/attribute")" == "$2" ]]; }
this_boot="$(cat /proc/sys/kernel/random/boot_id)"
reason_is() { [[ "$rc" == "$1" ]]; }

# The files: a is the real one, b and c differ by a comment.
rules=/rulesets
mkdir -p "$rules"
cp nftables.conf "${rules}/a"
{ cat nftables.conf; echo '# b'; } >"${rules}/b"
{ cat nftables.conf; echo '# c'; } >"${rules}/c"
printf 'table inet metadata_guard {\n  this is not a ruleset\n}\n' >"${rules}/broken"
printf 'table inet other {\n}\n' >"${rules}/no-guard"
# Names the guard in its comments, and doesn't define it.
printf '# chain metadata\ntable inet metadata_guard\ndelete table inet metadata_guard\ntable inet other {\n}\n' >"${rules}/fake-guard"
# Has the guard's chain, and nothing leads there.
printf 'table inet metadata_guard {\n  chain metadata {\n    meta skuid != 0 counter reject\n  }\n}\n' >"${rules}/unhooked"
# A good guard with a table the others lack, to tell which is in the kernel.
{ cat nftables.conf; printf 'table inet marked {\n}\n'; } >"${rules}/marked"
# Every name a guard has, and it lets every uid through.
sed 's/meta skuid != 0 counter reject with icmpx admin-prohibited/meta skuid != 0 accept/' nftables.conf >"${rules}/inverted"
# Reads as a guard, and only guards a port the token doesn't use.
sed 's/meta skuid != 0 counter reject/tcp dport 8080 meta skuid != 0 counter reject/' nftables.conf >"${rules}/narrow"
# Keeps root out too, so the token.
sed 's/meta skuid != 0 counter reject/tcp dport 80 reject\n\t\tmeta skuid != 0 counter reject/' nftables.conf >"${rules}/root-too"
# What the package ships.
printf 'flush ruleset\ntable inet filter {\n  chain output {\n    type filter hook output priority filter;\n  }\n}\n' >"${rules}/package"
sha_a="$(sha256sum "${rules}/a" | cut -d' ' -f1)"
sha_b="$(sha256sum "${rules}/b" | cut -d' ' -f1)"
sha_c="$(sha256sum "${rules}/c" | cut -d' ' -f1)"
sha_broken="$(sha256sum "${rules}/broken" | cut -d' ' -f1)"
sha_marked="$(sha256sum "${rules}/marked" | cut -d' ' -f1)"
# Nonces, in bootstrap.sh's shape (32 hex digits): this run's run and login nonces, and
# another run's.
run_a="$(printf '%032x' 10)"
run_b="$(printf '%032x' 11)"
login_a="$(printf '%032x' 20)"
login_b="$(printf '%032x' 21)"
# What startup.sh keeps of metadata's run nonce at each boot, and what /run holds.
run_nonce_file=/run/watchtower-run-nonce
give_run_nonce() { (umask 077 && printf '%s\n' "$run_a" >"$run_nonce_file"); }

# A bastion that has only ever had the package's ruleset, and no account.
fresh() {
  rm -rf "$state_dir" "$dropbox"
  rm -f /run/watchtower-ruleset.word /run/watchtower-ruleset.logins /run/watchtower-ruleset.tool
  give_run_nonce
  rm -f "${stubs}/load-broken" "${stubs}/timer-broken" "${stubs}/install-broken" \
    "${stubs}/nft-broken" "${stubs}/at-load-disk-fails" "${stubs}/at-load-a-login" \
    "${stubs}/sshd-start-broken" "${stubs}/sshd-down" "${stubs}/sshd-runs-its-gate" "${stubs}/ruleset-path" \
    "${stubs}/sshd-ungated"
  mkdir -p "$dropbox"
  chmod 1777 "$dropbox"
  cp "${rules}/package" /etc/nftables.conf
  nft flush ruleset
  echo 404 >"${stubs}/account-code"
  : >"${stubs}/calls"
}
# What a reboot does to all of it: nftables.service loads the file, the units
# start afresh, /run empties.
reboot_vm() {
  rm -f /run/watchtower-ruleset.word /run/watchtower-ruleset.logins /run/watchtower-ruleset.tool
  give_run_nonce
  nft flush ruleset
  [[ ! -e "${stubs}/load-broken" && -f /etc/nftables.conf ]] && nft --file /etc/nftables.conf 2>/dev/null
  rm -rf "$dropbox"
  mkdir -p "$dropbox"
  chmod 1777 "$dropbox"
  : >"${stubs}/calls"
}
# apply_ruleset <file> [<retry>]: as startup.sh calls it. Sets out and rc.
apply_ruleset() {
  : >"${stubs}/attribute"
  out="$(tool apply "${rules}/$1" "${2:-}" 2>&1)"
  rc=$?
}
fire() { : >"${stubs}/attribute"; out="$(tool rollback 2>&1)"; rc=$?; }
# A login's file, named as bootstrap.sh's job names it, then what the path unit starts.
confirm() { : >"${stubs}/attribute"; touch "${dropbox}/confirm-${login_a}"; out="$(tool confirm 2>&1)"; rc=$?; }
marked_on() { nft list table inet marked >/dev/null 2>&1; }

# A first install: no ruleset to go back to, and no account.
fresh
apply_ruleset a
check "first install: applied" reason_is 0
check "first install: says pending" state_is "$sha_a" pending
check "first install: installed" same_file "${rules}/a" /etc/nftables.conf
check "first install: keeps what was there" same_file "${rules}/package" "${state_dir}/nftables.old"
check "first install: the guard is on" guard_on
check "first install: records the trial" grep -qx "$sha_a" "${state_dir}/pending"
check "first install: arms the timer" called "restart ${timer}"
check "first install: starts sshd" called "start ssh.service"
check "first install: says which boot it is, with its run nonce" grep -qx "${this_boot} run ${run_a}" "${stubs}/attribute-boot"
check "first install: and its word has that boot's id" test "$(ruleset_state "$sha_a" "$this_boot" <"${stubs}/attribute")" = pending
check "first install: and that boot's run nonce" test "$(ruleset_state "$sha_a" "$this_boot" "$run_a" <"${stubs}/attribute")" = pending
check "first install: and isn't another run's" test -z "$(ruleset_state "$sha_a" "$this_boot" "$run_b" <"${stubs}/attribute")"
# line_of <call>: where it came in the order of what systemctl was asked.
line_of() { grep -nxF -- "$1" "${stubs}/calls" | head -1 | cut -d: -f1; }
trial_in_order() {
  [[ "$(line_of "restart ${timer}")" -lt "$(line_of 'stop ssh.service')" &&
    "$(line_of 'stop ssh.service')" -lt "$(line_of '--no-block stop user.slice')" &&
    "$(line_of '--no-block stop user.slice')" -lt "$(line_of 'reload-or-restart nftables.service')" &&
    "$(line_of 'reload-or-restart nftables.service')" -lt "$(line_of 'start ssh.service')" ]]
}
check "first install: armed, sshd and logins ended, loaded, sshd started, in that order" trial_in_order
fire
check "first install, fired: says rolled back" state_is "$sha_a" "rolled back"
check "first install, fired: puts back what was there" same_file "${rules}/package" /etc/nftables.conf
check "first install, fired: rejects it" test -e "${state_dir}/rejected/${sha_a}"
check "first install, fired: nothing pending" no_file "${state_dir}/pending"
check "first install, fired: reboots" called "--no-block reboot"
reboot_vm
refute "first install, after the reboot: no guard" guard_on
apply_ruleset a
check "first install, rejected: says rolled back again" state_is "$sha_a" "rolled back"
check "first install, rejected: not installed again" same_file "${rules}/package" /etc/nftables.conf
check "first install, rejected: nothing pending" no_file "${state_dir}/pending"
refute "first install, rejected: no timer" called "restart ${timer}"
refute "first install, rejected: no reboot, so no loop" called "--no-block reboot"
check "first install, rejected: sshd runs" called "start ssh.service"
check "first install, rejected: the package's has no guard, so on the floor" guard_on
check "first install, rejected: applied" reason_is 0

# Nothing runs with a token and no guard: gate, whatever else there is.
: >"${stubs}/calls"
echo 200 >"${stubs}/account-code"
nft flush ruleset
out="$(tool gate 2>&1)"; rc=$?
refute "gate: refuses a VM with an account and no guard" reason_is 0
echo 000 >"${stubs}/account-code"
out="$(tool gate 2>&1)"; rc=$?
refute "gate: refuses when the metadata server doesn't answer" reason_is 0
echo 200 >"${stubs}/account-code"
touch "${stubs}/nft-broken"
apply_ruleset a
check "gate: apply exits 1 when sshd may not run" reason_is 1
check "gate: apply stops sshd" called "stop ssh.service"
refute "gate: apply doesn't start sshd" called "start ssh.service"
if grep -q 'the way back is new metadata' <<<"$out"; then pass "ruleset: gate: says the way back"; else flunk "ruleset: gate: doesn't say the way back"; fi
rm -f "${stubs}/nft-broken"
echo 404 >"${stubs}/account-code"

# Confirming.
fresh
apply_ruleset a
setpriv --reuid=65534 --regid=65534 --clear-groups touch "${dropbox}/confirm"
check "a user may ask" test -e "${dropbox}/confirm"
# The tool word startup.sh's report_tool kept at this boot, once its apply ended well:
# what confirm says again in watchtower/tool, word for word. Not the installed tool's
# sha256 here, so it's the kept word that's said, not one worked out afresh.
kept_tool_word="$(printf '%064x' 99) boot ${this_boot} run ${run_a}"
printf '%s\n' "$kept_tool_word" >/run/watchtower-ruleset.tool
rm -f "${stubs}/attribute-tool"
confirm
check "confirm: says confirmed" state_is "$sha_a" confirmed
check "confirm: says the kept tool word again" grep -qxF "$kept_tool_word" "${stubs}/attribute-tool"
check "confirm: nothing pending" no_file "${state_dir}/pending"
check "confirm: records it" grep -qx "$sha_a" "${state_dir}/confirmed"
check "confirm: stops the timer" called "stop ${timer}"
check "confirm: empties the directory" no_file "${dropbox}/confirm"
check "confirm: reports a login, on this boot, with this run's nonces" login_seen "$this_boot" "$run_a" "$login_a" <"${stubs}/attribute-login"
refute "confirm: not as another run's login" login_seen "$this_boot" "$run_a" "$login_b" <"${stubs}/attribute-login"
refute "confirm: not with another run nonce" login_seen "$this_boot" "$run_b" "$login_a" <"${stubs}/attribute-login"
# The login nonces: this boot's, the newest last, eight at most, and only a name of
# exactly that shape, read from the name alone.
# login_list: what the last login attribute listed.
login_list() { sed -n 's/^login [0-9]* boot [0-9a-f-]* for \([^ ]*\) run .*$/\1/p' "${stubs}/attribute-login"; }
# Each login in a pass of its own, as the path unit runs, so the order is theirs.
touch "${dropbox}/confirm-${login_b}"
out="$(tool confirm 2>&1)"
check "login nonces: two logins, both listed, the newest last" test "$(login_list)" = "${login_a},${login_b}"
touch "${dropbox}/plain-login"
out="$(tool confirm 2>&1)"
check "login nonces: a plain login keeps them" test "$(login_list)" = "${login_a},${login_b}"
for n in 30 31 32 33 34 35 36 37 38; do
  touch "${dropbox}/confirm-$(printf '%032x' "$n")"
  out="$(tool confirm 2>&1)"
done
check "login nonces: eight at most, the newest kept" test "$(login_list)" = "$(for n in 31 32 33 34 35 36 37 38; do printf '%032x\n' "$n"; done | paste -sd,)"
touch "${dropbox}/confirm-$(printf '%031x' 1)" "${dropbox}/confirm-$(printf '%032x' 2)x" "${dropbox}/confirm-$(printf '%032X' 171)" \
  "${dropbox}/confirm-$(printf '%032x' 3),$(printf '%032x' 4)"
# A name with a newline in it, which a line-by-line read would split into two.
touch "${dropbox}/confirm-$(printf '%032x' 5)"$'\n'"confirm-$(printf '%032x' 6)"
out="$(tool confirm 2>&1)"
check "login nonces: no name of another shape listed" test "$(login_list)" = "$(for n in 31 32 33 34 35 36 37 38; do printf '%032x\n' "$n"; done | paste -sd,)"
rm -f /run/watchtower-ruleset.logins
touch "${dropbox}/plain-login"
out="$(tool confirm 2>&1)"
check "login nonces: none at all is -" test "$(login_list)" = -
# The run nonce: each attribute carries this boot's, and "-" without one.
rm -f "$run_nonce_file"
touch "${dropbox}/confirm-${login_a}"
out="$(tool confirm 2>&1)"
check "run nonce: none is -" grep -q ' run -$' "${stubs}/attribute-login"
refute "run nonce: none is no login bootstrap counts" login_seen "$this_boot" "$run_a" "$login_a" <"${stubs}/attribute-login"
printf 'not-a-nonce\n' >"$run_nonce_file"
touch "${dropbox}/confirm-${login_a}"
out="$(tool confirm 2>&1)"
check "run nonce: one of another shape is -" grep -q ' run -$' "${stubs}/attribute-login"
give_run_nonce
: >"${stubs}/calls"
fire
refute "confirm: a late timer does nothing" called "--no-block reboot"
check "confirm: a late timer leaves the ruleset" same_file "${rules}/a" /etc/nftables.conf
reboot_vm
apply_ruleset a
check "confirm: says so at the next boot" state_is "$sha_a" confirmed
refute "confirm: no timer at the next boot" called "restart ${timer}"
check "confirm: the guard is on at the next boot" guard_on
refute "confirm: a boot with no change ends no one's sessions" called "--no-block stop user.slice"
refute "confirm: a boot with no change doesn't stop sshd" called "stop ssh.service"
: >"${stubs}/calls"
rm -f "${stubs}/attribute-login"
confirm
refute "confirm: with nothing pending, nothing" called "stop ${timer}"
check "confirm: with nothing pending, the login is still reported" login_seen "$this_boot" "$run_a" "$login_a" <"${stubs}/attribute-login"

# confirmed means sshd is up too. An sshd that won't start, at a boot with no change.
reboot_vm
touch "${stubs}/sshd-start-broken" "${stubs}/sshd-down"
apply_ruleset a
check "sshd won't start: exit 1" reason_is 1
check "sshd won't start: says failed" state_is "$sha_a" failed
refute "sshd won't start: doesn't say confirmed" state_is "$sha_a" confirmed
sshd_down_word="$(cat "${stubs}/attribute")"
rm -f "${stubs}/sshd-start-broken" "${stubs}/sshd-down"
apply_ruleset a
check "sshd starts again: says confirmed" state_is "$sha_a" confirmed
# Starts, and doesn't stay up.
touch "${stubs}/sshd-down"
apply_ruleset a
check "sshd doesn't stay up: says failed" state_is "$sha_a" failed
rm -f "${stubs}/sshd-down"

# A word the attribute lost stays lost for the boot, unless a login says it again.
reboot_vm
touch "${stubs}/attribute-broken"
apply_ruleset a
rm -f "${stubs}/attribute-broken"
check "a lost word: nothing reached the attribute" test ! -s "${stubs}/attribute"
check "a lost word: it did say so" reason_is 0
# watchtower/tool too, which startup.sh says once at a boot whose apply ended well, and
# keeps for a login to say again.
install -m 0755 ruleset.sh /usr/local/sbin/watchtower-ruleset
printf '%s\n' "$kept_tool_word" >/run/watchtower-ruleset.tool
rm -f "${stubs}/attribute-tool"
confirm
check "a lost word: a login says it again" state_is "$sha_a" confirmed
check "a lost word: and the tool word, again" grep -qxF "$kept_tool_word" "${stubs}/attribute-tool"
# A boot whose apply never ended well keeps no tool word (startup.sh's guard died before
# report_tool): a login then says confirmed of the ruleset, if that's true, and nothing
# of the tool, so bootstrap's final check can't pass on it (the review's case,
# 2026-11-04).
rm -f /run/watchtower-ruleset.tool "${stubs}/attribute-tool"
confirm
check "no kept tool word: a login still says the ruleset's" state_is "$sha_a" confirmed
check "no kept tool word: and nothing of the tool" no_file "${stubs}/attribute-tool"
# ... only while it's true.
touch "${stubs}/sshd-down"
confirm
refute "a lost word: not with sshd down" state_is "$sha_a" confirmed
rm -f "${stubs}/sshd-down"
nft flush ruleset
confirm
refute "a lost word: not with the guard off" state_is "$sha_a" confirmed
nft --file nftables.conf
reboot_vm

# A login from before the load shows nothing about the new ruleset, even when it
# was queued behind apply's lock: the load takes its file with it.
apply_ruleset b
confirm
reboot_vm
touch "${stubs}/at-load-a-login"
apply_ruleset c
rm -f "${stubs}/at-load-a-login"
check "an early login: says pending" state_is "$sha_c" pending
check "an early login: its file went with the load" test -z "$(find "$dropbox" -mindepth 1 -print -quit)"
out="$(tool confirm 2>&1)"; rc=$?
check "an early login: still pending" test -e "${state_dir}/pending"
refute "an early login: the timer stays" called "stop ${timer}"
confirm
check "an early login: a later one confirms" no_file "${state_dir}/pending"
# A process from before the load, which outlives it, doing what a login does. A
# trial ends it, and nothing it left behind can confirm.
reboot_vm
as_user bash -c 'while :; do touch /run/watchtower-ruleset/left-behind 2>/dev/null; sleep 0.1; done' &
left_behind=$!
sleep 0.5
check "a process from before the load: it's running" test -e "${dropbox}/left-behind"
apply_ruleset a 20
check "a process from before the load: says pending" state_is "$sha_a" pending
check "a process from before the load: it's gone" proc_gone "$left_behind"
sleep 0.5
check "a process from before the load: its file went, and none came after" test -z "$(find "$dropbox" -mindepth 1 -print -quit)"
out="$(tool confirm 2>&1)"; rc=$?
check "a process from before the load: can't confirm" test -e "${state_dir}/pending"
wait "$left_behind" 2>/dev/null
confirm
check "a process from before the load: a later login confirms" no_file "${state_dir}/pending"
fresh
apply_ruleset a
confirm
reboot_vm

# A second ruleset, with an old one to go back to.
apply_ruleset b
check "second: says pending" state_is "$sha_b" pending
check "second: keeps the old one" same_file "${rules}/a" "${state_dir}/nftables.old"
reboot_vm
apply_ruleset b
check "re-arm after a reboot: says pending" state_is "$sha_b" pending
check "re-arm after a reboot: arms the timer" called "restart ${timer}"
check "re-arm after a reboot: old one still the old one" same_file "${rules}/a" "${state_dir}/nftables.old"
check "re-arm after a reboot: the guard is on" guard_on
apply_ruleset c
check "a third over a trial: says pending" state_is "$sha_c" pending
check "a third over a trial: an unconfirmed one is no old one" same_file "${rules}/a" "${state_dir}/nftables.old"
: >"${stubs}/calls"
apply_ruleset a
check "back to the confirmed one, mid-trial: says confirmed" state_is "$sha_a" confirmed
check "back to the confirmed one, mid-trial: installed" same_file "${rules}/a" /etc/nftables.conf
check "back to the confirmed one, mid-trial: nothing pending" no_file "${state_dir}/pending"
check "back to the confirmed one, mid-trial: stops the timer" called "stop ${timer}"

# Fired, with an old one, then a fix and a retry.
apply_ruleset b
fire
check "fired: says rolled back" state_is "$sha_b" "rolled back"
check "fired: the old ruleset back" same_file "${rules}/a" /etc/nftables.conf
check "fired: reboots" called "--no-block reboot"
reboot_vm
apply_ruleset b
check "rejected: says so" state_is "$sha_b" "rolled back"
check "rejected: stays on the old one" same_file "${rules}/a" /etc/nftables.conf
check "rejected: the guard is on" guard_on
check "rejected: sshd runs" called "start ssh.service"
refute "rejected: no reboot, so no loop" called "--no-block reboot"
touch "${dropbox}/a-login"
out="$(tool confirm 2>&1)"; rc=$?
check "rejected: a login doesn't say confirmed over it" state_is "$sha_b" "rolled back"
apply_ruleset b 1
check "retry: tried again" state_is "$sha_b" pending
fire
reboot_vm
apply_ruleset b 1
check "retry: the same retry again stays rejected" state_is "$sha_b" "rolled back"
apply_ruleset b 2
check "retry: a new retry tries again" state_is "$sha_b" pending
fire
reboot_vm
apply_ruleset c
check "a fixed file: tried, as its sha256 is new" state_is "$sha_c" pending
check "a fixed file: the old one is still the good one" same_file "${rules}/a" "${state_dir}/nftables.old"
confirm
reboot_vm

# Files that never go on.
apply_ruleset broken
check "broken: refused" state_is "$sha_broken" refused
touch "${dropbox}/a-login"
out="$(tool confirm 2>&1)"; rc=$?
check "broken: a login doesn't say confirmed over it" state_is "$sha_broken" refused
check "broken: not installed" same_file "${rules}/c" /etc/nftables.conf
check "broken: nothing pending" no_file "${state_dir}/pending"
check "broken: sshd runs" called "start ssh.service"
apply_ruleset no-guard
check "no guard: refused" reason_is 0
check "no guard: not installed" same_file "${rules}/c" /etc/nftables.conf
# ... and one that only names the guard, has it with nothing leading there, lets
# every uid through, reads as a guard and doesn't do the job, or keeps root out too,
# never reaches the live kernel: it's tried where nothing can see it.
for sneaky in fake-guard unhooked inverted narrow root-too; do
  reboot_vm
  apply_ruleset "$sneaky"
  sneaky_sha="$(sha256sum "${rules}/${sneaky}" | cut -d' ' -f1)"
  check "${sneaky}: refused" state_is "$sneaky_sha" refused
  check "${sneaky}: not installed" same_file "${rules}/c" /etc/nftables.conf
  check "${sneaky}: nothing pending" no_file "${state_dir}/pending"
  check "${sneaky}: never loaded, so the live guard stays" guard_on
  refute "${sneaky}: never loaded, so no reboot" called "--no-block reboot"
  refute "${sneaky}: never loaded, so no one's sessions end" called "--no-block stop user.slice"
done
# The real ruleset passes all of that, with the same test, or nothing above shows
# anything.
check "the real ruleset: does a guard's job in the namespace" env PATH="${stubs}:${PATH}" unshare --net bash /check/ruleset.sh probe nftables.conf
# What the gate and the ping go by, of what's in the kernel now: its rules, not its
# name.
loaded_is() { tool loaded >/dev/null 2>&1; }
gate_says() { tool gate >/dev/null 2>&1; }
refuses_is() { tool refuses-users >/dev/null 2>&1; }
echo 200 >"${stubs}/account-code"
for bad_kernel in inverted fake-guard unhooked; do
  nft flush ruleset
  nft --file "${rules}/${bad_kernel}"
  refute "the kernel, ${bad_kernel}: not loaded" loaded_is
  refute "the kernel, ${bad_kernel}: the gate refuses it, on a VM with an account" gate_says
done
echo 404 >"${stubs}/account-code"
nft flush ruleset
nft --file "${rules}/narrow"
refute "the kernel, narrow: a user reaches the server, as the live test shows" refuses_is
nft flush ruleset
nft --file nftables.conf
check "the kernel, the real one: loaded" loaded_is
check "the kernel, the real one: a user is refused" refuses_is
tool floor
check "the kernel, the floor: loaded" loaded_is
reboot_vm
# A file that passes that and still won't load live, or leaves no guard there.
touch "${stubs}/load-broken"
apply_ruleset b 7
rm -f "${stubs}/load-broken"
check "gone after the load: exit says it is rebooting" reason_is 75
check "gone after the load: says rolled back" state_is "$sha_b" "rolled back"
check "gone after the load: the old one back" same_file "${rules}/c" /etc/nftables.conf
check "gone after the load: rejected" test -e "${state_dir}/rejected/${sha_b}"
check "gone after the load: reboots" called "--no-block reboot"
reboot_vm

# The disk won't take the old ruleset back when the timer fires.
apply_ruleset marked
confirm
reboot_vm
apply_ruleset a 8
check "restore fails: a on trial, over marked" state_is "$sha_a" pending
nft delete table inet marked
touch "${stubs}/install-broken"
: >"${stubs}/calls"
fire
refute "restore fails: the service fails, so it retries" reason_is 0
check "restore fails: says failed" state_is "$sha_a" failed
if grep -q 'rolled back' <<<"$out"; then flunk "ruleset: restore fails: says rolled back"; else pass "ruleset: restore fails: doesn't say rolled back"; fi
check "restore fails: the old one is in the kernel anyway" marked_on
check "restore fails: the record stays" test -e "${state_dir}/pending"
check "restore fails: rejected, so no login brings it back" test -e "${state_dir}/rejected/${sha_a}"
check "restore fails: a is still on disk" same_file "${rules}/a" /etc/nftables.conf
refute "restore fails: no reboot, so no reboot loop" called "--no-block reboot"
# ... a login in the meantime changes nothing.
confirm
check "restore fails: a login can't confirm it" test -e "${state_dir}/pending"
refute "restore fails: a login leaves the retries" called "stop ${timer}"
# ... the next boot brings sshd up on what it can, and keeps trying.
reboot_vm
nft delete table inet marked 2>/dev/null
apply_ruleset b 9
check "restore fails, next boot: exit 0, as sshd may run" reason_is 0
check "restore fails, next boot: the old one in the kernel" marked_on
check "restore fails, next boot: sshd runs" called "start ssh.service"
check "restore fails, next boot: the retries go on" called "--no-block start watchtower-ruleset-rollback.service"
check "restore fails, next boot: says failed" state_is "$sha_a" failed
if grep -q "ruleset [a-z]* ${sha_b}" <<<"$out"; then flunk "ruleset: restore fails, next boot: took a new file first"; else pass "ruleset: restore fails, next boot: finishes the rollback first"; fi
check "restore fails, next boot: the record stays" test -e "${state_dir}/pending"
# ... and once the disk takes it, it finishes.
rm -f "${stubs}/install-broken"
: >"${stubs}/calls"
fire
check "restore works at last: exit 0" reason_is 0
check "restore works at last: says rolled back" state_is "$sha_a" "rolled back"
check "restore works at last: the old one on disk" same_file "${rules}/marked" /etc/nftables.conf
check "restore works at last: nothing pending" no_file "${state_dir}/pending"
check "restore works at last: reboots" called "--no-block reboot"
reboot_vm

# A file that won't load, and then the disk won't take the old one back either.
touch "${stubs}/load-broken" "${stubs}/at-load-disk-fails"
: >"${stubs}/calls"
apply_ruleset b 10
rm -f "${stubs}/load-broken" "${stubs}/at-load-disk-fails"
check "won't load, can't restore: no rollback claimed, so no 75" reason_is 0
check "won't load, can't restore: says failed" state_is "$sha_b" failed
if grep -q 'rolled back' <<<"$out"; then flunk "ruleset: won't load, can't restore: says rolled back"; else pass "ruleset: won't load, can't restore: doesn't say rolled back"; fi
check "won't load, can't restore: the record stays" test -e "${state_dir}/pending"
refute "won't load, can't restore: no reboot" called "--no-block reboot"
check "won't load, can't restore: retries" called "--no-block start watchtower-ruleset-rollback.service"
# ... and the rerun that used to read it as confirmed finishes the rollback.
rm -f "${stubs}/install-broken"
apply_ruleset b 11
check "won't load, can't restore, rerun: finishes it" reason_is 75
check "won't load, can't restore, rerun: says rolled back" state_is "$sha_b" "rolled back"
check "won't load, can't restore, rerun: the old one back" same_file "${rules}/marked" /etc/nftables.conf
if grep -qx "$sha_b" "${state_dir}/confirmed"; then flunk "ruleset: won't load, can't restore, rerun: recorded as confirmed"; else pass "ruleset: won't load, can't restore, rerun: never recorded as confirmed"; fi
reboot_vm

# Reverting to the confirmed file in the middle of a trial, with a disk that
# won't take it: the trial's rollback is all there is, so it stays.
apply_ruleset b 12
touch "${stubs}/install-broken"
: >"${stubs}/calls"
apply_ruleset marked
rm -f "${stubs}/install-broken"
check "revert can't install: says failed" state_is "$sha_marked" failed
refute "revert can't install: not confirmed" state_is "$sha_marked" confirmed
check "revert can't install: the trial stands" grep -qx "$sha_b" "${state_dir}/pending"
refute "revert can't install: the timer stands" called "stop ${timer}"
check "revert can't install: the trial's file is still there" same_file "${rules}/b" /etc/nftables.conf
apply_ruleset marked
check "revert can install: says confirmed" state_is "$sha_marked" confirmed
check "revert can install: nothing pending" no_file "${state_dir}/pending"
reboot_vm

# A file that has stopped loading is no way back: the last that loaded stays.
cp "${rules}/marked" "${state_dir}/nftables.old"
cp /etc/nftables.conf "${rules}/kept"
cp "${rules}/broken" /etc/nftables.conf
reboot_vm
apply_ruleset b 13
check "stopped loading: b on trial" state_is "$sha_b" pending
check "stopped loading: the old one stays the old one" same_file "${rules}/marked" "${state_dir}/nftables.old"
fire
check "stopped loading, fired: back to one that loads" same_file "${rules}/marked" /etc/nftables.conf
reboot_vm
check "stopped loading, fired: the guard is on at the next boot" guard_on
apply_ruleset marked
check "stopped loading, fired: says confirmed" state_is "$sha_marked" confirmed

# A file rejected here and still on disk with no record, which no path above
# leaves but a lost state file could: asked for again, it's a trial. It never
# reads as no change, so as confirmed with no login.
cp "${rules}/b" /etc/nftables.conf
: >"${state_dir}/rejected/${sha_b}"
reboot_vm
apply_ruleset b 14
check "rejected and on disk: a retry is a trial" state_is "$sha_b" pending
check "rejected and on disk: not its own way back" same_file "${rules}/marked" "${state_dir}/nftables.old"
fire
reboot_vm
apply_ruleset c 15
confirm
reboot_vm

# The power goes between rejecting it and putting the old one back.
apply_ruleset b 3
: >"${state_dir}/rejected/${sha_b}"
apply_ruleset b
check "power cut mid-rollback: finishes it" reason_is 75
check "power cut mid-rollback: the old one back" same_file "${rules}/c" /etc/nftables.conf
reboot_vm

# No timer, no trial.
touch "${stubs}/timer-broken"
: >"${stubs}/calls"
apply_ruleset a 16
check "no timer: not installed" same_file "${rules}/c" /etc/nftables.conf
check "no timer: nothing pending" no_file "${state_dir}/pending"
check "no timer: sshd still runs" called "start ssh.service"
rm -f "${stubs}/timer-broken"
# ... and a trial already running can't go on without one.
apply_ruleset b 4
check "no timer, mid-trial: b on trial" state_is "$sha_b" pending
touch "${stubs}/timer-broken"
reboot_vm
apply_ruleset b
check "no timer, mid-trial: exit says it is rebooting" reason_is 75
check "no timer, mid-trial: says rolled back" state_is "$sha_b" "rolled back"
check "no timer, mid-trial: the old one back" same_file "${rules}/c" /etc/nftables.conf
check "no timer, mid-trial: rejected" test -e "${state_dir}/rejected/${sha_b}"
check "no timer, mid-trial: reboots" called "--no-block reboot"
rm -f "${stubs}/timer-broken"
reboot_vm
# ... nor a third over it: the one on disk ends, and the third hasn't started.
apply_ruleset a 17
check "no timer, a third over a trial: a on trial" state_is "$sha_a" pending
touch "${stubs}/timer-broken"
reboot_vm
apply_ruleset b 5
check "no timer, a third over a trial: exit says it is rebooting" reason_is 75
check "no timer, a third over a trial: the one on disk rolled back" state_is "$sha_a" "rolled back"
check "no timer, a third over a trial: the old one back" same_file "${rules}/c" /etc/nftables.conf
check "no timer, a third over a trial: the third isn't rejected" no_file "${state_dir}/rejected/${sha_b}"
rm -f "${stubs}/timer-broken"
reboot_vm

# The guard fails to load at a boot with no ruleset change.
touch "${stubs}/load-broken"
reboot_vm
refute "boot, no change, no load: no guard yet" guard_on
rm -f "${state_dir}/confirmed"
apply_ruleset c
check "boot, no change, no load: applied" reason_is 0
check "boot, no change, no load: says failed, for bootstrap to stop on" state_is "$sha_c" failed
refute "boot, no change, no load: doesn't say confirmed" state_is "$sha_c" confirmed
check "boot, no change, no load: no record of it" no_file "${state_dir}/confirmed"
check "boot, no change, no load: a guard in the kernel, the old one or the floor" guard_on
check "boot, no change, no load: the file stays" same_file "${rules}/c" /etc/nftables.conf
check "boot, no change, no load: sshd runs" called "start ssh.service"
# ... and the old one won't load either: the floor.
cp "${rules}/broken" "${state_dir}/nftables.old"
reboot_vm
echo 200 >"${stubs}/account-code"
apply_ruleset c
check "boot, neither loads, an account: the floor is on" guard_on
check "boot, neither loads, an account: says failed" state_is "$sha_c" failed
check "boot, neither loads, an account: applied" reason_is 0
check "boot, neither loads, an account: sshd runs, guarded" called "start ssh.service"
# ... and not even that: nft itself.
touch "${stubs}/nft-broken"
reboot_vm
apply_ruleset c
check "nft loads nothing, an account: exit 1" reason_is 1
refute "nft loads nothing, an account: no guard" guard_on
refute "nft loads nothing, an account: sshd stays down" called "start ssh.service"
check "nft loads nothing, an account: sshd stopped" called "stop ssh.service"
rm -f "${stubs}/nft-broken"
# ... and on new metadata, the way back.
rm -f "${stubs}/load-broken"
apply_ruleset a 6
check "new metadata brings it back: says pending" state_is "$sha_a" pending
check "new metadata brings it back: installed" same_file "${rules}/a" /etc/nftables.conf
check "new metadata brings it back: applied" reason_is 0
check "new metadata brings it back: the guard is on" guard_on
check "new metadata brings it back: sshd runs" called "start ssh.service"
echo 404 >"${stubs}/account-code"

# No ruleset in metadata: what's on disk stays.
: >"${stubs}/calls"
out="$(tool apply 2>&1)"; rc=$?
check "no metadata: applied" reason_is 0
check "no metadata: sshd runs" called "start ssh.service"

# What a user can do. Pending, with a user's files of every kind in the way.
fresh
apply_ruleset a
: >"${stubs}/calls"
out="$(as_user bash /check/ruleset.sh rollback 2>&1)"; rc=$?
refute "a user: can't fire it" reason_is 0
out="$(as_user bash /check/ruleset.sh apply "${rules}/b" 2>&1)"; rc=$?
refute "a user: can't apply" reason_is 0
out="$(as_user bash /check/ruleset.sh confirm 2>&1)"; rc=$?
refute "a user: can't run confirm itself" reason_is 0
refute "a user: no reboot" called "--no-block reboot"
check "a user: still pending" test -e "${state_dir}/pending"
check "a user: the ruleset stays" same_file "${rules}/a" /etc/nftables.conf
as_user ln -s /etc/nftables.conf "${dropbox}/a-link"
as_user mkdir "${dropbox}/a-directory"
as_user touch "${dropbox}/a-directory/a-file"
as_user mkfifo "${dropbox}/a-fifo"
: >"${dropbox}/roots"
out="$(as_user rm -f "${dropbox}/roots" 2>&1)"; rc=$?
check "a user: can't remove another's file, as the directory is sticky" test -e "${dropbox}/roots"
confirm
check "a user's files: confirm says confirmed" state_is "$sha_a" confirmed
check "a user's files: the directory is empty" test -z "$(find "$dropbox" -mindepth 1 -print -quit)"
check "a user's files: a link's target stays" same_file "${rules}/a" /etc/nftables.conf

# No old file at all: the rollback leaves none.
fresh
rm -f /etc/nftables.conf
apply_ruleset a
check "nothing there: no old one" no_file "${state_dir}/nftables.old"
fire
check "nothing there, fired: none again" no_file /etc/nftables.conf
check "nothing there, fired: reboots" called "--no-block reboot"

# Telling the attribute never changes what came of it.
fresh
touch "${stubs}/attribute-broken"
apply_ruleset a
rm -f "${stubs}/attribute-broken"
check "no attribute: applied" reason_is 0
check "no attribute: the trial runs" test -e "${state_dir}/pending"
check "no attribute: sshd runs" called "start ssh.service"
if grep -q 'could not put that in the guest attribute' <<<"$out"; then pass "ruleset: no attribute: says so"; else flunk "ruleset: no attribute: says nothing"; fi
# ... and it's real output too, for whoever reads the console.
apply_ruleset a
if grep -qF "bastion: ruleset pending ${sha_a} at " <<<"$out"; then pass "ruleset: a line for the console too"; else flunk "ruleset: no line for the console"; fi

# bootstrap.sh's reading of the attribute: that ruleset's, and that boot's.
boot_a="aaaaaaaa-0000-4000-8000-000000000001"
boot_b="bbbbbbbb-0000-4000-8000-000000000002"
now="$(date +%s)"
# read_state <value> <sha> <boot> <want> [<run nonce>]
read_state() { [[ "$(ruleset_state "$2" "$3" "${5:-}" <<<"$1")" == "$4" ]]; }
check "bootstrap reads: one word" read_state "confirmed ${sha_a} at 200 boot ${boot_a} run ${run_a}" "$sha_a" "$boot_a" confirmed
check "bootstrap reads: two words" read_state "rolled back ${sha_b} at 300 boot ${boot_a} run ${run_a}" "$sha_b" "$boot_a" "rolled back"
check "bootstrap reads: refused" read_state "refused ${sha_c} at 400 boot ${boot_a} run ${run_a}" "$sha_c" "$boot_a" refused
check "bootstrap reads: failed" read_state "failed ${sha_c} at 400 boot ${boot_a} run ${run_a}" "$sha_c" "$boot_a" failed
check "bootstrap reads: any boot's, when asked" read_state "rolled back ${sha_b} at 300 boot ${boot_a} run ${run_a}" "$sha_b" "" "rolled back"
check "bootstrap reads: not an earlier boot's" read_state "confirmed ${sha_a} at 200 boot ${boot_b} run ${run_a}" "$sha_a" "$boot_a" ""
check "bootstrap reads: not without a boot" read_state "confirmed ${sha_a} at 200 run ${run_a}" "$sha_a" "" ""
check "bootstrap reads: another ruleset's are no news" read_state "confirmed ${sha_b} at 200 boot ${boot_a} run ${run_a}" "$sha_a" "$boot_a" ""
check "bootstrap reads: nothing from nothing" test -z "$(ruleset_state "$sha_a" "$boot_a" </dev/null)"
check "bootstrap reads: not ten years from now" read_state "confirmed ${sha_a} at $((now + 315360000)) boot ${boot_a} run ${run_a}" "$sha_a" "$boot_a" ""
check "bootstrap reads: a minute of clock skew is fine" read_state "confirmed ${sha_a} at $((now + 60)) boot ${boot_a} run ${run_a}" "$sha_a" "$boot_a" confirmed
# Only the value, whole: not a serial line of any shape, which any user can write.
check "bootstrap reads: not a console line" read_state "bastion: ruleset confirmed ${sha_a} at 200 boot ${boot_a} run ${run_a}" "$sha_a" "$boot_a" ""
check "bootstrap reads: not one inside another" read_state "x confirmed ${sha_a} at 200 boot ${boot_a} run ${run_a}" "$sha_a" "$boot_a" ""
# The run nonce: this run's, when asked for one.
check "bootstrap reads: this run's nonce" read_state "confirmed ${sha_a} at 200 boot ${boot_a} run ${run_a}" "$sha_a" "$boot_a" confirmed "$run_a"
check "bootstrap reads: not another run's" read_state "confirmed ${sha_a} at 200 boot ${boot_a} run ${run_b}" "$sha_a" "$boot_a" "" "$run_a"
check "bootstrap reads: not a boot with no run nonce" read_state "confirmed ${sha_a} at 200 boot ${boot_a} run -" "$sha_a" "$boot_a" "" "$run_a"
check "bootstrap reads: not a value without one at all" read_state "confirmed ${sha_a} at 200 boot ${boot_a}" "$sha_a" "$boot_a" ""
check "bootstrap reads: not one with more after it" read_state "confirmed ${sha_a} at 200 boot ${boot_a} run ${run_a} x" "$sha_a" "$boot_a" "" "$run_a"
# And a login: on that boot, with this run's run nonce and login nonce, and no later than now.
# saw_login <value> <boot> [<run nonce>] [<login nonce>]
saw_login() { login_seen "$2" "${3-$run_a}" "${4-$login_a}" <<<"$1"; }
check "bootstrap reads a login: this boot, this run" saw_login "login ${now} boot ${boot_a} for ${login_a} run ${run_a}" "$boot_a"
check "bootstrap reads a login: among others of the boot" saw_login "login ${now} boot ${boot_a} for ${login_b},${login_a} run ${run_a}" "$boot_a"
check "bootstrap reads a login: an older one of this run" saw_login "login $((now - 3600)) boot ${boot_a} for ${login_a} run ${run_a}" "$boot_a"
refute "bootstrap reads a login: not an earlier run's, though on this boot and recent" saw_login "login ${now} boot ${boot_a} for ${login_b} run ${run_a}" "$boot_a"
refute "bootstrap reads a login: not one with no login nonce" saw_login "login ${now} boot ${boot_a} for - run ${run_a}" "$boot_a"
refute "bootstrap reads a login: not with another run nonce" saw_login "login ${now} boot ${boot_a} for ${login_a} run ${run_b}" "$boot_a"
refute "bootstrap reads a login: not with no run nonce" saw_login "login ${now} boot ${boot_a} for ${login_a} run -" "$boot_a"
refute "bootstrap reads a login: not when it has no login nonce to look for" saw_login "login ${now} boot ${boot_a} for ${login_a} run ${run_a}" "$boot_a" "$run_a" ""
refute "bootstrap reads a login: not another boot's" saw_login "login ${now} boot ${boot_b} for ${login_a} run ${run_a}" "$boot_a"
refute "bootstrap reads a login: not one from the future" saw_login "login $((now + 3600)) boot ${boot_a} for ${login_a} run ${run_a}" "$boot_a"
refute "bootstrap reads a login: not a console line" saw_login "bastion: login ${now} boot ${boot_a} for ${login_a} run ${run_a}" "$boot_a"
refute "bootstrap reads a login: not a nonce inside another" saw_login "login ${now} boot ${boot_a} for x${login_a} run ${run_a}" "$boot_a"
refute "bootstrap reads a login: not the old shape" saw_login "login ${now} boot ${boot_a}" "$boot_a"
refute "bootstrap reads a login: not nothing" saw_login "" "$boot_a"

# bootstrap.sh's wait. The attribute's values, in turn, from a file of them, with
# watchtower/boot saying which boot it is, and with which run nonce.
# wait_case <name> <want exit> <want dispatches> <the boot before a restart, or "">
#   <values, one a line> [<the boot it says it's on>] [<the run nonce it says that with>]
BASTION=watchtower-bastion
BASTION_ZONE=stand-in-zone
GCP_PROJECT=stand-in-project
confirm_by_hand="the-hand-confirm"
ruleset_sha="$sha_a"
attribute_error=/tmp/attribute-error
# This run's nonces, as bootstrap.sh holds them.
run_nonce="$run_a"
login_nonce="$login_a"
wait_case() {
  local name=$1 want_rc=$2 want_dispatches=$3 old_boot=$4 values=$5 says_boot=${6-$boot_a} says_run=${7-$run_a} got rc
  printf '%s\n' "$values" >"${stubs}/values"
  got="$(
    bastion_attribute() {
      if [[ "$1" == boot ]]; then
        [[ -z "$says_boot" ]] || printf '%s run %s\n' "$says_boot" "$says_run"
        return
      fi
      # The next value, the last one staying.
      local value
      value="$(head -1 "${stubs}/values")"
      [[ "$(wc -l <"${stubs}/values")" -le 1 ]] || sed -i 1d "${stubs}/values"
      printf '%s\n' "$value"
    }
    bastion_dispatch() { echo dispatched; }
    log() { printf '%s\n' "$*"; }
    die() { printf 'died: %s\n' "$*"; exit 1; }
    sleep() { :; }
    bastion_ruleset_wait "$old_boot"
  )"
  rc=$?
  local dispatches
  dispatches="$(grep -c '^dispatched$' <<<"$got")"
  if [[ "$rc" == "$want_rc" && "$dispatches" == "$want_dispatches" ]]; then
    pass "bootstrap waits: ${name}"
  else
    flunk "bootstrap waits: ${name}: exit ${rc}, ${dispatches} dispatches; want exit ${want_rc}, ${want_dispatches} dispatches"
  fi
  wait_out="$got"
}
# word <state> [<boot>] [<sha>] [<epoch>] [<run nonce>]: a ruleset attribute's value.
word() { printf '%s %s at %s boot %s run %s' "$1" "${3:-$sha_a}" "${4:-200}" "${2:-$boot_a}" "${5:-$run_a}"; }
wait_case "confirmed" 0 0 "" "$(word confirmed)"
wait_case "pending, then confirmed: dispatches once" 0 1 "" "$(word pending)
$(word pending)
$(word confirmed)"
if grep -qF "$confirm_by_hand" <<<"$wait_out"; then pass "bootstrap waits: says how to confirm by hand"; else flunk "bootstrap waits: doesn't say how to confirm by hand"; fi
wait_case "rolled back stops" 1 0 "" "$(word 'rolled back')"
# A tool stopped at its time limit mid-trial ends rolled back too: the message names it,
# and that a retry would hang the same way (the review's fix, 2026-11-04).
if grep -qF 'says "apply took longer than", the ruleset tool hung in its trial and was stopped at its time limit, and a retry would hang the same way' <<<"$wait_out"; then
  pass "bootstrap waits: rolled back names the tool's time limit, and the serial output's line"
else
  flunk "bootstrap waits: rolled back says: ${wait_out}"
fi
wait_case "pending, then rolled back stops" 1 1 "" "$(word pending)
$(word 'rolled back')"
wait_case "refused stops, as a rerun finds it" 1 0 "" "$(word refused)"
wait_case "failed stops" 1 0 "" "$(word failed)"
if grep -qF 'or its ruleset tool was stopped at its time limit, which the serial output then says ("apply took longer than"' <<<"$wait_out"; then
  pass "bootstrap waits: failed names the tool's time limit, and the serial output's line"
else
  flunk "bootstrap waits: failed says: ${wait_out}"
fi
wait_case "an earlier boot's word isn't this boot's" 1 0 "" "$(word confirmed "$boot_b")"
wait_case "after a restart, the old boot's word isn't one, while the VM still says that boot" 1 0 "$boot_a" "$(word confirmed)"
wait_case "after a restart, the new boot's word is" 0 0 "$boot_b" "$(word confirmed)"
wait_case "no boot reported is no word" 1 0 "" "$(word confirmed)" ""
wait_case "another ruleset's word isn't this one's" 1 0 "" "$(word confirmed "$boot_a" "$sha_b")"
wait_case "a date in the future isn't a word" 1 0 "" "$(word confirmed "$boot_a" "$sha_a" "$((now + 315360000))")"
wait_case "a forged console line isn't a word" 1 0 "" "bastion: ruleset $(word confirmed)"
wait_case "nothing at all stops, in the end" 1 0 "" ""
# What the tool itself said above, of an sshd that wouldn't start: no success.
wait_case "confirmed with sshd down, in the tool's own words, stops" 1 0 "" "$sshd_down_word" "$this_boot"
# The run nonce (the owner's decision, 2026-11-04): only values with this start's count.
wait_case "this start's nonce on the boot and the word" 0 0 "" "$(word confirmed)"
wait_case "a word of another run's isn't this one's" 1 0 "" "$(word confirmed "$boot_a" "$sha_a" 200 "$run_b")"
wait_case "a word from a boot with no run nonce isn't one" 1 0 "" "$(word confirmed "$boot_a" "$sha_a" 200 -)"
wait_case "a boot said with another run's nonce isn't this one" 1 0 "" "$(word confirmed)" "$boot_a" "$run_b"
# What a user could leave on the boot with no account, for the next to be taken by: a
# made-up boot, and its word, with the nonce that boot had. The next start's is new.
wait_case "values planted before this start, with the nonce of the boot before, are no word" 1 0 "$boot_b" \
  "$(word confirmed "$boot_a" "$sha_a" 200 "$run_b")" "$boot_a" "$run_b"
no_nonce_wait="$(
  run_nonce=""
  bastion_attribute() { echo "should not be asked"; }
  log() { :; }
  die() { printf 'died: %s\n' "$*"; exit 1; }
  sleep() { :; }
  bastion_ruleset_wait ""
)"
if [[ "$no_nonce_wait" == "died: no run nonce"* ]]; then pass "bootstrap waits: with no run nonce, stops before it asks"; else flunk "bootstrap waits: with no run nonce: ${no_nonce_wait}"; fi

# A guest attribute that isn't there yet, and one that can't be read.
attribute_case() {
  local name=$1 want=$2 message=$3 got
  : >"$attribute_error"
  got="$(
    compute() { echo "$message" >&2; return 1; }
    guest_attribute watchtower/ruleset 2>&1
    attribute_refusal
  )"
  case "$want" in
    quiet) if [[ -z "$got" ]]; then pass "bootstrap reads attributes: ${name}"; else flunk "bootstrap reads attributes: ${name}: ${got}"; fi ;;
    refused) if [[ "$got" == *refused*refused* ]]; then pass "bootstrap reads attributes: ${name}"; else flunk "bootstrap reads attributes: ${name}: ${got}"; fi ;;
  esac
}
attribute_case "not there yet says nothing" quiet "ERROR: HTTPError 404: The resource 'guestAttributes/watchtower/ruleset' was not found"
attribute_case "no permission says so, now and when it gives up" refused "ERROR: PERMISSION_DENIED: Required 'compute.instances.getGuestAttributes' permission"
attribute_case "turned off says so, now and when it gives up" refused "ERROR: Guest attributes are disabled"
if [[ "$(compute() { echo a-value; }; guest_attribute watchtower/ruleset)" == a-value ]]; then pass "bootstrap reads attributes: a value"; else flunk "bootstrap reads attributes: no value"; fi
# ... all the way to the message the owner is left with.
refused_wait="$(
  compute() { echo 'ERROR: PERMISSION_DENIED: no' >&2; return 1; }
  log() { :; }
  die() { printf 'died: %s\n' "$*"; exit 1; }
  sleep() { :; }
  bastion_ruleset_wait "" 2>/dev/null
)"
if [[ "$refused_wait" == *"was refused"*PERMISSION_DENIED* ]]; then pass "bootstrap waits: says the reads were refused, not only that nothing came"; else flunk "bootstrap waits: gives up with: ${refused_wait}"; fi

# bootstrap.sh's wait for a login.
# login_case <name> <want exit> <want dispatches> <values, one a line>
login_case() {
  local name=$1 want_rc=$2 want_dispatches=$3 values=$4 got rc
  printf '%s\n' "$values" >"${stubs}/values"
  got="$(
    bastion_attribute() {
      local value
      value="$(head -1 "${stubs}/values")"
      [[ "$(wc -l <"${stubs}/values")" -le 1 ]] || sed -i 1d "${stubs}/values"
      printf '%s\n' "$value"
    }
    bastion_dispatch() { echo dispatched; }
    log() { printf '%s\n' "$*"; }
    die() { printf 'died: %s\n' "$*"; exit 1; }
    sleep() { :; }
    bastion_login_wait "$boot_a"
  )"
  rc=$?
  local dispatches
  dispatches="$(grep -c '^dispatched$' <<<"$got")"
  if [[ "$rc" == "$want_rc" && "$dispatches" == "$want_dispatches" ]]; then
    pass "bootstrap waits for a login: ${name}"
  else
    flunk "bootstrap waits for a login: ${name}: exit ${rc}, ${dispatches} dispatches; want exit ${want_rc}, ${want_dispatches} dispatches"
  fi
}
# login_word <boot> [<login nonces>] [<run nonce>] [<epoch>]: a login attribute's value.
login_word() { printf 'login %s boot %s for %s run %s' "${4:-$now}" "$1" "${2:-$login_a}" "${3:-$run_a}"; }
login_case "there already: no job" 0 0 "$(login_word "$boot_a")"
login_case "none, so the job, then it comes" 0 1 "
$(login_word "$boot_a")"
login_case "another boot's doesn't count, and the job runs" 0 1 "$(login_word "$boot_b")
$(login_word "$boot_a")"
login_case "none ever: stops" 1 1 ""
# The login nonce (the owner's decision, 2026-11-04): a rerun can't be satisfied by an
# earlier run's login, however recent, on the very boot it asks about.
login_case "only an earlier run's login, on this boot and just now: stops" 1 1 "$(login_word "$boot_a" "$login_b")"
login_case "only a login with no nonce: stops" 1 1 "$(login_word "$boot_a" -)"
login_case "an earlier run's, then this run's: the job, then it counts" 0 1 "$(login_word "$boot_a" "$login_b")
$(login_word "$boot_a" "${login_b},${login_a}")"
login_case "this run's login nonce, with another run nonce: stops" 1 1 "$(login_word "$boot_a" "$login_a" "$run_b")"
# What the final check then goes by: the boot the wait saw the login reach.
seen_after_wait="$(
  bastion_attribute() { login_word "$boot_a"; }
  bastion_dispatch() { :; }
  log() { :; }
  sleep() { :; }
  login_seen_boot=""
  bastion_login_wait "$boot_a" >/dev/null
  echo "$login_seen_boot"
)"
check "bootstrap waits for a login: keeps the boot it saw it on" test "$seen_after_wait" = "$boot_a"

# --- bootstrap: bastion_update, in order, with gcloud stubbed --------------------
# update_trace <metadata differs?> <account differs?> [the compute call that fails]
# [the run nonce the VM has, or "none"]: prints everything it does, and "exit <n>"
# last; the add-metadata that sets a run nonce is "compute-run-nonce". Under set -e
# and the real exit trap, as bootstrap.sh runs it. The run nonce each wait was asked
# with goes in /tmp/update-trace-nonces, the VM's first.
update_trace() {
  local meta=$1 account=$2 failing=${3:-} had=${4:-$run_a}
  [[ "$had" != none ]] || had=""
  printf '%s\n' "${had:-none}" >/tmp/update-trace-nonces
  (
    set -e
    n=0
    bastion_files=stand-in-files
    BASTION_SA=stand-in-account
    current='{"meta":{"startup-script":"old"}}'
    want="$current"
    [[ "$meta" != yes ]] || want='{"meta":{"startup-script":"new"}}'
    account_differs=""
    [[ "$account" != yes ]] || account_differs=1
    retry_args=()
    stop_in_flight=""
    run_nonce="$had"
    cleanup=/tmp/update-trace-cleanup
    log() { :; }
    die() { echo died; exit 1; }
    sleep() { :; }
    compute() {
      if [[ "$2" == describe ]]; then
        echo TERMINATED
        # Not a bare return: in a trap, that gives the status from before the trap.
        return 0
      fi
      local call="$2"
      [[ "$*" != *watchtower-run-nonce=* ]] || call=run-nonce
      echo "compute-${call}"
      [[ "$call" != "$failing" ]]
    }
    bastion_attribute() {
      case "$1" in
        # The boot before, said with the run nonce it was started with.
        boot) echo "dead-beef run ${had}" ;;
        settled) echo "${bastion_boot_id} run ${settled_with:-$run_nonce}" ;;
      esac
    }
    bastion_ruleset_wait() {
      n=$((n + 1))
      echo "wait-after-${1:-nothing}"
      echo "$run_nonce" >>/tmp/update-trace-nonces
      bastion_boot_id="boot-${n}"
    }
    bastion_login_wait() { echo "login-on-$1"; }
    trap bastion_on_exit EXIT
    bastion_update
  ) 2>/dev/null
  echo "exit $?"
}
# Not through check: set -e does nothing inside an if, and it's what's under test.
# update_case <name> <want> <metadata differs?> <account differs?> [what fails] [the VM's run nonce]
update_case() {
  local name=$1 want=$2 got
  got="$(update_trace "$3" "$4" "${5:-}" "${6:-}")"
  got="${got//$'\n'/ }"
  if [[ "$got" == "$want" ]]; then pass "update: ${name}"; else flunk "update: ${name}: ${got}"; fi
}
update_case "both differ: metadata before the stop, a stop for the account, a run nonce while stopped each time, each boot asked, and a login last" \
  "compute-add-metadata compute-stop compute-run-nonce compute-start wait-after-dead-beef compute-stop compute-set-service-account compute-run-nonce compute-start wait-after-boot-1 login-on-boot-2 exit 0" yes yes
update_case "only the metadata: one restart, with a run nonce while stopped" \
  "compute-add-metadata compute-stop compute-run-nonce compute-start wait-after-dead-beef login-on-boot-1 exit 0" yes no
update_case "only the account: goes by this boot, then asks the new one, with a run nonce while stopped" \
  "wait-after-nothing compute-stop compute-set-service-account compute-run-nonce compute-start wait-after-boot-1 login-on-boot-2 exit 0" no yes
update_case "nothing differs: no restart, and it's still asked, with a login" \
  "wait-after-nothing login-on-boot-1 exit 0" no no
update_case "nothing differs, and no run nonce yet: started afresh to get one" \
  "compute-add-metadata compute-stop compute-run-nonce compute-start wait-after-nothing login-on-boot-1 exit 0" no no "" none
update_case "metadata refused: never stopped, and the failure stands" \
  "compute-add-metadata exit 1" yes no add-metadata
update_case "a stop that fails: started anyway, with a fresh run nonce, and the failure stands" \
  "compute-add-metadata compute-stop compute-run-nonce compute-start exit 1" yes no stop
# The exit trap's start gets a fresh run nonce too, or, refused one, none at all, so the
# next run starts it afresh rather than trust one the boot before could show.
update_case "the run nonce refused: the exit trap tries again, removes the old one, starts it, and the failure stands" \
  "compute-add-metadata compute-stop compute-run-nonce compute-run-nonce compute-remove-metadata compute-start exit 1" yes no run-nonce
update_case "the account refused: the exit trap starts it, with a fresh run nonce, and the failure stands" \
  "wait-after-nothing compute-stop compute-set-service-account compute-run-nonce compute-start exit 1" no yes set-service-account
update_case "the account on, then the run nonce refused: the old one removed before the boot with the account" \
  "wait-after-nothing compute-stop compute-set-service-account compute-run-nonce compute-run-nonce compute-remove-metadata compute-start exit 1" no yes run-nonce
# apt's word said with another run's nonce: no account goes on.
settled_with="$run_b"
update_case "settled with another run's nonce: never stopped for the account" \
  "wait-after-nothing died exit 1" no yes
settled_with=""
# Each start gets a nonce of its own, of bootstrap's shape, and none the VM had before;
# a run that starts nothing asks by the one its boot has.
update_trace yes yes >/dev/null
mapfile -t trace_nonces </tmp/update-trace-nonces
if [[ "${#trace_nonces[@]}" == 3 && "${trace_nonces[1]}" =~ ^[0-9a-f]{32}$ && "${trace_nonces[2]}" =~ ^[0-9a-f]{32}$ &&
  "${trace_nonces[1]}" != "${trace_nonces[2]}" && "${trace_nonces[1]}" != "$run_a" && "${trace_nonces[2]}" != "$run_a" ]]; then
  pass "update: two starts, two fresh run nonces, neither the one the VM had"
else
  flunk "update: the waits were asked with: ${trace_nonces[*]}"
fi
update_trace no no >/dev/null
mapfile -t trace_nonces </tmp/update-trace-nonces
if [[ "${trace_nonces[*]}" == "${run_a} ${run_a}" ]]; then pass "update: no start, so asked by the VM's own run nonce"; else flunk "update: with no start, asked with: ${trace_nonces[*]}"; fi

# The exit trap alone: the status it came with, whatever the start does.
# trap_trace <in flight> <start's status> <polls still STOPPING before TERMINATED>
#   [<the run nonce's add-metadata's status>]
trap_trace() {
  local in_flight=$1 start_rc=$2 stopping=${3:-0} nonce_rc=${4:-0}
  echo 0 >/tmp/trap-polls
  (
    cleanup=/tmp/update-trace-cleanup
    stop_in_flight="$in_flight"
    sleep() { echo slept; }
    compute() {
      if [[ "$2" == describe ]]; then
        local polls
        polls="$(($(cat /tmp/trap-polls) + 1))"
        echo "$polls" >/tmp/trap-polls
        if [[ "$polls" -gt "$stopping" ]]; then echo TERMINATED; else echo STOPPING; fi
        # Not a bare return: in a trap, that gives the status from before the trap.
        return 0
      fi
      if [[ "$*" == *watchtower-run-nonce=* ]]; then
        echo compute-run-nonce
        return "$nonce_rc"
      fi
      echo "compute-$2"
      [[ "$2" != start ]] || return "$start_rc"
    }
    trap bastion_on_exit EXIT
    exit 7
  ) 2>/dev/null
  echo "exit $?"
}
trap_is() { [[ "$(trap_trace "$2" "$3" "${4:-0}" "${5:-0}" | tr '\n' ' ')" == "$1 " ]]; }
check "exit trap: a stop in flight: a fresh run nonce, starts it, keeps the status" trap_is "compute-run-nonce compute-start exit 7" 1 0
check "exit trap: the start fails too: keeps the status" trap_is "compute-run-nonce compute-start exit 7" 1 1
check "exit trap: nothing in flight: leaves it alone" trap_is "exit 7" "" 0
check "exit trap: still stopping: waits for that, then starts" trap_is "slept slept compute-run-nonce compute-start exit 7" 1 0 2
check "exit trap: the run nonce refused: the old one removed, then starts it" trap_is "compute-run-nonce compute-remove-metadata compute-start exit 7" 1 0 0 1
trap_never="$(trap_trace 1 0 1000 | tr '\n' ' ')"
if [[ "$trap_never" == "$(printf 'slept %.0s' {1..24})compute-run-nonce compute-start exit 7 " ]]; then
  pass "ruleset: exit trap: never stopped: waits 2 minutes at most, then tries anyway"
else
  flunk "ruleset: exit trap: never stopped: ${trap_never}"
fi
# bastion_up, which starts a VM an earlier run left stopped: with a fresh run nonce too.
# up_trace <the run nonce's add-metadata's status>
up_trace() {
  local nonce_rc=$1
  (
    log() { :; }
    sleep() { :; }
    compute() {
      if [[ "$2" == describe ]]; then
        echo TERMINATED
        return 0
      fi
      if [[ "$*" == *watchtower-run-nonce=* ]]; then
        echo compute-run-nonce
        return "$nonce_rc"
      fi
      echo "compute-$2"
    }
    bastion_up
  ) 2>/dev/null | tr '\n' ' '
}
up_is() { [[ "$(up_trace "$2")" == "$1 " ]]; }
check "bastion_up: a stopped VM: a fresh run nonce, then started" up_is "compute-run-nonce compute-start" 0
check "bastion_up: the run nonce refused: the old one removed, then started" up_is "compute-run-nonce compute-remove-metadata compute-start" 1

# The last word before "Done".
# final_is <want exit> <status> <boot attribute> <ruleset attribute> <login attribute>
#   [<tool attribute>]
tool_sha="$(sha256sum ruleset.sh | cut -d' ' -f1)"
# What the login wait saw (login_seen_boot) and the userns attribute come from
# final_seen and final_userns, set around a case.
final_seen=""
final_userns="off boot ${boot_a} run ${run_a}"
final_is() {
  local want_rc=$1 vm_status=$2 says_boot=$3 ruleset=$4 login=$5 tool_says=${6-"${tool_sha} boot ${boot_a} run ${run_a}"} rc
  (
    bastion_boot_id="$boot_a"
    login_seen_boot="$final_seen"
    compute() { echo "$vm_status"; }
    bastion_attribute() {
      case "$1" in
        boot) echo "$says_boot" ;;
        ruleset) echo "$ruleset" ;;
        login) echo "$login" ;;
        tool) echo "$tool_says" ;;
        userns) echo "$final_userns" ;;
      esac
    }
    die() { echo "died: $*" >&2; exit 1; }
    bastion_final_check
  ) >/dev/null 2>/tmp/final-stderr
  rc=$?
  [[ "$rc" == "$want_rc" ]]
}
boot_word="${boot_a} run ${run_a}"
final_login="$(login_word "$boot_a")"
check "final check: running, this boot, confirmed, this tool, a login of this run" final_is 0 RUNNING "$boot_word" "$(word confirmed)" "$final_login"
check "final check: stopped" final_is 1 TERMINATED "$boot_word" "$(word confirmed)" "$final_login"
check "final check: running, and it has rebooted since" final_is 1 RUNNING "${boot_b} run ${run_a}" "$(word confirmed "$boot_b")" "$(login_word "$boot_b")"
check "final check: running, and says no boot" final_is 1 RUNNING "" "$(word confirmed)" "$final_login"
check "final check: running, and sshd has failed since" final_is 1 RUNNING "$boot_word" "$(word failed)" "$final_login"
check "final check: running, and no login" final_is 1 RUNNING "$boot_word" "$(word confirmed)" ""
check "final check: running, and only an earlier run's login" final_is 1 RUNNING "$boot_word" "$(word confirmed)" "$(login_word "$boot_a" "$login_b")"
check "final check: running, and the boot said with another run's nonce" final_is 1 RUNNING "${boot_a} run ${run_b}" "$(word confirmed)" "$final_login"
check "final check: running, and confirmed with another run's nonce" final_is 1 RUNNING "$boot_word" "$(word confirmed "$boot_a" "$sha_a" 200 "$run_b")" "$final_login"
# The tool it runs: this ruleset.sh, or no Done (it failed its self-check, or fell back).
check "final check: running, and another tool" final_is 1 RUNNING "$boot_word" "$(word confirmed)" "$final_login" \
  "$(printf '%064x' 1) boot ${boot_a} run ${run_a}"
check "final check: running, and no tool said" final_is 1 RUNNING "$boot_word" "$(word confirmed)" "$final_login" ""
check "final check: running, and this tool said with another run's nonce" final_is 1 RUNNING "$boot_word" "$(word confirmed)" "$final_login" \
  "${tool_sha} boot ${boot_a} run ${run_b}"
check "final check: another tool's message names a lost word, and a login or a reset" \
  grep -q 'or the VM lost that word, which a login or a reset says again' /tmp/final-stderr
# A login the wait saw on this boot stands, though a user on the VM has since pushed this
# run's nonce out of the eight the attribute keeps; one it saw on another boot doesn't.
pushed_out="$(login_word "$boot_a" "$(for n in 40 41 42 43 44 45 46 47; do printf '%032x\n' "$n"; done | paste -sd,)")"
final_seen="$boot_a"
check "final check: the login the wait saw, pushed out of the attribute since, stands" final_is 0 RUNNING "$boot_word" "$(word confirmed)" "$pushed_out"
final_seen="$boot_b"
check "final check: a login the wait saw on another boot doesn't" final_is 1 RUNNING "$boot_word" "$(word confirmed)" "$pushed_out"
final_seen=""
check "final check: and none seen, none in the attribute: no Done" final_is 1 RUNNING "$boot_word" "$(word confirmed)" "$pushed_out"
# User namespaces: a warning when this boot says they're on, or says nothing, never a stop.
final_userns="on boot ${boot_a} run ${run_a}"
check "final check: user namespaces on: still Done" final_is 0 RUNNING "$boot_word" "$(word confirmed)" "$final_login"
check "final check: user namespaces on: warns" grep -q 'has unprivileged user namespaces on' /tmp/final-stderr
final_userns="off boot ${boot_a} run ${run_b}"
check "final check: user namespaces said off with another run's nonce: still Done" final_is 0 RUNNING "$boot_word" "$(word confirmed)" "$final_login"
check "final check: user namespaces said off with another run's nonce: warns it heard nothing" grep -q 'said nothing at this boot of whether unprivileged user namespaces are off' /tmp/final-stderr
final_userns="off boot ${boot_a} run ${run_a}"
check "final check: user namespaces off: no warning" final_is 0 RUNNING "$boot_word" "$(word confirmed)" "$final_login"
refute "final check: user namespaces off: says nothing of them" grep -q 'user namespaces' /tmp/final-stderr

# The units, as systemd reads them.
fresh
install -m 0755 ruleset.sh /usr/local/sbin/watchtower-ruleset
check "units: setup" tool setup
verify="$(systemd-analyze verify --man=no \
  watchtower-ruleset-rollback.timer watchtower-ruleset-rollback.service \
  watchtower-ruleset-confirm.path watchtower-ruleset-confirm.service \
  watchtower-ruleset-floor.service 'run-watchtower\x2druleset.mount' \
  ssh.service nftables.service 2>&1)"
vrc=$?
if [[ "$vrc" == 0 && -z "$(grep -E 'watchtower|ssh\.service|nftables\.service' <<<"$verify")" ]]; then
  pass "units: systemd-analyze verify"
else
  flunk "units: systemd-analyze verify: ${verify}"
fi
check "units: enabled" called "enable --quiet nftables.service ${timer} watchtower-ruleset-confirm.path"
check "units: a restart never flushes the guard" grep -qx 'ExecStop=' /etc/systemd/system/nftables.service.d/watchtower.conf
check "units: sshd asks the gate" grep -qx 'ExecStartPre=/usr/local/sbin/watchtower-ruleset gate' /etc/systemd/system/ssh.service.d/watchtower-guard.conf
refute "units: a restart of the guard doesn't take sshd down" grep -qE '^(Requires|BindsTo|PartOf|Requisite)=' /etc/systemd/system/ssh.service.d/watchtower-guard.conf
check "units: the timer comes back only with a trial" grep -qx 'ConditionPathExists=/var/lib/watchtower-bastion/pending' /etc/systemd/system/${timer}
check "units: 10 minutes" grep -qx 'OnActiveSec=10min' /etc/systemd/system/${timer}
mount_unit='/etc/systemd/system/run-watchtower\x2druleset.mount'
check "units: the directory is sticky, open to all and tiny" grep -qx 'Options=mode=1777,size=64k,nr_inodes=1024,nosuid,nodev,noexec' "$mount_unit"
check "units: the path unit waits for it" grep -qx 'RequiresMountsFor=/run/watchtower-ruleset' /etc/systemd/system/watchtower-ruleset-confirm.path
check "units: serial output from the rollback" grep -qx 'StandardOutput=journal+console' /etc/systemd/system/watchtower-ruleset-rollback.service
check "units: serial output from the confirmation" grep -qx 'StandardOutput=journal+console' /etc/systemd/system/watchtower-ruleset-confirm.service
check "units: the rollback retries" grep -qx 'Restart=on-failure' /etc/systemd/system/watchtower-ruleset-rollback.service
check "units: for as long as it takes" grep -qx 'StartLimitIntervalSec=0' /etc/systemd/system/watchtower-ruleset-rollback.service
check "units: a ruleset that fails to load brings the floor" grep -qx 'OnFailure=watchtower-ruleset-floor.service' /etc/systemd/system/nftables.service.d/watchtower.conf
check "units: the floor goes on before the network" grep -qx 'Before=network-pre.target' /etc/systemd/system/watchtower-ruleset-floor.service
# Nothing of a user's runs without a login. Cron itself says what setup changed:
# with its allow file gone a user may add a crontab, and then may not.
rm -f /etc/cron.allow
printf '@reboot touch /tmp/a-users-job\n' | as_user crontab -
check "units, cron: a user can add a crontab without it" test "$?" = 0
check "units, cron: there it is" test -n "$(find /var/spool/cron/crontabs -mindepth 1 -print -quit)"
mkdir -p /var/lib/systemd/linger
touch /var/lib/systemd/linger/nobody
check "units, cron: setup again" tool setup
check "units, cron: the one from before is gone" test -z "$(find /var/spool/cron/crontabs -mindepth 1 -print -quit)"
check "units, linger: the one from before is gone" no_file /var/lib/systemd/linger/nobody
printf '@reboot touch /tmp/a-users-job\n' | as_user crontab - 2>/dev/null
refute "units, cron: a user can't add one now" test "$?" = 0
check "units, cron: nor did it stay" test -z "$(find /var/spool/cron/crontabs -mindepth 1 -print -quit)"
check "units, cron: root only" grep -qx root /etc/cron.allow
check "units, at: root only" grep -qx root /etc/at.allow
# at's spool, where it's installed: a user's job goes, and root's stays.
mkdir -p /var/spool/cron/atjobs
touch /var/spool/cron/atjobs/a-users-job /var/spool/cron/atjobs/roots-job
chown 65534 /var/spool/cron/atjobs/a-users-job
check "units, at: setup again" tool setup
check "units, at: the one from before is gone" no_file /var/spool/cron/atjobs/a-users-job
check "units, at: root's stays" test -e /var/spool/cron/atjobs/roots-job
# polkit's rule, under the JavaScript engine polkit uses here, as polkit would call
# it, since logind and polkit don't run in this container.
{
  echo 'var rule; var polkit = {Result: {NO: "refused"}, addRule: function (f) { rule = f; }};'
  cat /etc/polkit-1/rules.d/10-watchtower-ruleset.rules
  echo 'print(rule({id: "org.freedesktop.login1.set-self-linger"}, {user: "a-user"}));'
  echo 'print(rule({id: "org.freedesktop.login1.set-user-linger"}, {user: "a-user"}));'
  echo 'print(rule({id: "org.freedesktop.login1.reboot"}, {user: "a-user"}));'
} >/tmp/polkit-rule.js
linger_answers="$(duk /tmp/polkit-rule.js | tr '\n' ' ')"
if [[ "$linger_answers" == "refused refused undefined " ]]; then
  pass "units, linger: a user's own and another's refused, and nothing else touched"
else
  flunk "units, linger: polkit's rule answers: ${linger_answers}"
fi
# The floor: the same guard as the file, and it holds.
nft flush ruleset
nft --file nftables.conf
file_guard="$(nft list table inet metadata_guard)"
check "floor: loads" tool floor
floor_guard="$(nft list table inet metadata_guard)"
if [[ "$file_guard" == "$floor_guard" ]]; then pass "ruleset: floor: the same guard as nftables.conf"; else flunk "ruleset: floor: not the same guard as nftables.conf"; fi
probe 0 "$meta" tcp 80 open
probe 65534 "$meta" tcp 80 refused
probe 65534 "$meta" udp 9999 refused
probe 65534 "$meta" udp 53 open
probe 65534 "$meta" udp 67 open
probe 65534 "$meta" udp 123 open
# The lock: a user can't open it, so can't hold up a rollback by holding it.
if as_user bash -c 'exec 9</run/watchtower-ruleset.lock' 2>/dev/null; then flunk "ruleset: a user can open the lock"; else pass "ruleset: a user can't open the lock"; fi
# The login's own part: it asks, and a shell without the directory doesn't care.
mkdir -p "$dropbox"
chmod 1777 "$dropbox"
as_user sh -c '. /etc/profile.d/watchtower-ruleset.sh'
check "units: a login asks" test -n "$(find "$dropbox" -mindepth 1 -print -quit)"
rm -rf "$dropbox"
as_user sh -c 'set -e; . /etc/profile.d/watchtower-ruleset.sh; true'
check "units: a login with no directory is unharmed" test "$?" = 0

# --- ping, through the real script: real curl's place taken, nothing else's ------
# The metadata server, Secret Manager and Healthchecks.io, as curl would find them.
ping_bin="${stubs}/ping-bin"
mkdir -p "$ping_bin"
chmod 0755 "$ping_bin"
cat >"${ping_bin}/curl" <<'STUB'
#!/bin/bash
# Every argument it's given goes in a file: the test looks for the URL there.
printf '%s\n' "$*" >>/tmp/ping-all-args
out=/dev/null
url=""
config=""
args=("$@")
for ((i = 0; i < $#; i++)); do
  case "${args[i]}" in
    -o) out="${args[i + 1]}" ;;
    -K) config="$(cat)"; printf '%s\n' "$config" >>/tmp/ping-all-stdin ;;
    http*) url="${args[i]}" ;;
  esac
done
case "$url" in
  */token)
    echo '{"access_token":"stand-in-for-the-token"}' >"$out"
    printf 200
    ;;
  */healthchecks-bastion-url/versions/latest:access)
    printf '{"payload":{"data":"%s"}}' "$(base64 -w0 </tmp/ping-secret-value)" >"$out"
    printf 200
    ;;
  "")
    # The ping itself: its URL only in the config.
    [[ ! -e /tmp/ping-broken ]]
    ;;
esac
STUB
chmod 0755 "${ping_bin}/curl"
printf '%s' "$ping_stand_in" >/tmp/ping-secret-value
# ping_tool [as_user]: the timer's way in. Sets out and rc.
ping_tool() {
  rm -f /tmp/ping-all-args /tmp/ping-all-stdin
  out="$("$@" env PATH="${ping_bin}:${stubs}:${PATH}" bash /check/startup.sh ping 2>&1)"
  rc=$?
}
held_back() { [[ "$out" != *stand-in-for* && "$(cat /tmp/ping-all-args 2>/dev/null)" != *stand-in-for* ]]; }
said() { grep -qF -- "$1" <<<"$out"; }
fresh
nft --file nftables.conf
ping_tool
check "ping, real script: exit 0" reason_is 0
check "ping, real script: says so" said 'pinged the Healthchecks.io check'
check "ping, real script: curl gets the URL on stdin" grep -qxF "url = \"${ping_stand_in}\"" /tmp/ping-all-stdin
check "ping, real script: and the token" grep -qxF 'header = "Authorization: Bearer stand-in-for-the-token"' /tmp/ping-all-stdin
check "ping, real script: neither in an argument or the output" held_back
touch /tmp/ping-broken
ping_tool
rm -f /tmp/ping-broken
check "ping, real script, it fails: exit 0" reason_is 0
check "ping, real script, it fails: says so" said 'could not ping the Healthchecks.io check'
check "ping, real script, it fails: the URL stays out" held_back
touch "${stubs}/sshd-down"
ping_tool
rm -f "${stubs}/sshd-down"
check "ping, real script, sshd down: exit 0" reason_is 0
check "ping, real script, sshd down: says so" said "sshd isn't active"
refute "ping, real script, sshd down: reads no secret" test -e /tmp/ping-all-args
# A user: the guard's own test above shows the metadata server refuses them, and
# this that it never gets that far.
ping_tool setpriv --reuid=65534 --regid=65534 --clear-groups
check "ping, a user: exit 0" reason_is 0
refute "ping, a user: reads no secret" test -e /tmp/ping-all-args
check "ping, a user: says why" said 'no metadata guard'
nft flush ruleset
ping_tool
check "ping, real script, no guard: exit 0" reason_is 0
check "ping, real script, no guard: says so" said 'no metadata guard'
refute "ping, real script, no guard: reads no secret" test -e /tmp/ping-all-args

# ... its units, as systemd reads them, and nothing stops if they can't be written.
fresh
ping_units_out="$(work="$(mktemp -d)"; PATH="${stubs}:${PATH}" ping_setup 2>&1)"
check "ping units: this file, on disk" same_file startup.sh /usr/local/sbin/watchtower-startup
check "ping units: the timer's on" called "enable --now --quiet watchtower-ping.timer"
check "ping units: an hour after the 04:00 reboot" grep -qx 'OnCalendar=\*-\*-\* 05:00:00 UTC' /etc/systemd/system/watchtower-ping.timer
check "ping units: run this file with ping" grep -qx 'ExecStart=/usr/local/sbin/watchtower-startup ping' /etc/systemd/system/watchtower-ping.service
ping_verify="$(systemd-analyze verify --man=no watchtower-ping.timer watchtower-ping.service 2>&1)"
vrc=$?
if [[ "$vrc" == 0 && -z "$(grep 'watchtower' <<<"$ping_verify")" ]]; then
  pass "ping units: systemd-analyze verify"
else
  flunk "ping units: systemd-analyze verify: ${ping_verify}"
fi
# No unit anywhere names it but its own two, and they ask for nothing to wait on
# them: so nothing of sshd, the guard or the rollback can depend on it.
ping_mentions="$(grep -Rl 'watchtower-ping' /etc/systemd/system /usr/lib/systemd/system 2>/dev/null | grep -vE '/watchtower-ping\.(service|timer)$')"
check "ping units: no other unit names them" test -z "$ping_mentions"
refute "ping units: nothing is made to need them" grep -qE '^(RequiredBy|WantedBy|Before)=' /etc/systemd/system/watchtower-ping.service
check "ping units: says nothing when all goes well" test -z "$ping_units_out"

# --- tool: startup.sh's self-check of a new ruleset.sh, and its last good copy -----
real_tool=/usr/local/sbin/watchtower-ruleset
last_good=/usr/local/sbin/watchtower-ruleset.last-good
variants=/tool-variants
mkdir -p "$variants"
# The same tool, a comment apart: an older copy.
sed '2i # an older copy' ruleset.sh >"${variants}/older"
# Bugs a self-check has to see, each in a tool that otherwise parses and is whole:
# sshd's gate saying yes with no guard; no rules taken for a guard; a floor that lets
# users through; a floor nft refuses.
sed 's/^gate() {$/&\n  return 0/' ruleset.sh >"${variants}/gate-yes"
sed 's/^guard_loaded() {$/&\n  return 0/' ruleset.sh >"${variants}/loaded-yes"
sed 's/meta skuid != 0 counter reject with icmpx admin-prohibited$/meta skuid != 0 accept/' ruleset.sh >"${variants}/floor-open"
sed 's/^\t\tip daddr 169.254.169.254 jump metadata$/\t\tip daddr 169.254.169.254 jump nowhere/' ruleset.sh >"${variants}/floor-broken"
head -n 40 ruleset.sh >"${variants}/cut-short"
# sshd's gate saying no even with the guard on.
sed 's/^gate() {$/&\n  return 1/' ruleset.sh >"${variants}/gate-no"
# And ones it can't: apply fails at a boot, before it starts sshd; apply ends at once,
# saying all is well and starting nothing; apply hangs, holding the lock.
sed 's/^cmd_apply() {$/&\n  exit 1/' ruleset.sh >"${variants}/apply-fails"
sed 's/^cmd_apply() {$/&\n  exit 0/' ruleset.sh >"${variants}/apply-zero"
sed '/^cmd_apply() {$/,/^}$/ s/^  lock$/  lock\n  sleep 1000/' ruleset.sh >"${variants}/apply-hangs"
chmod 0755 "$variants"/*
# Each mutant is what its name says, or the cases below prove nothing.
for variant in gate-yes loaded-yes floor-open floor-broken gate-no apply-fails apply-zero apply-hangs; do
  if cmp -s ruleset.sh "${variants}/${variant}"; then flunk "tool: the ${variant} mutant is the real tool"; fi
done

# tool_as <file or none> <last good copy, or none> [settled]: what's on disk before a
# boot, on a VM with an account (so a gate with no guard must say no), with sshd down
# until something starts it through its gate, as with its drop-in. A first install
# unless settled: then ruleset a is on and confirmed, so the boot has no trial.
tool_as() {
  fresh
  echo 200 >"${stubs}/account-code"
  touch "${stubs}/sshd-down" "${stubs}/sshd-runs-its-gate"
  rm -f "$real_tool" "$last_good"
  [[ "$1" == none ]] || install -m 0755 "$1" "$real_tool"
  [[ "$2" == none ]] || install -m 0755 "$2" "$last_good"
  if [[ "${3:-}" == settled ]]; then
    cp "${rules}/a" /etc/nftables.conf
    install -d -m 0700 "$state_dir" "${state_dir}/rejected"
    echo "$sha_a" >"${state_dir}/confirmed"
    nft --file "${rules}/a"
  fi
}
# boot_with_tool <the tool in metadata, or none>: startup.sh's guard, as at a boot, with
# metadata offering that tool and nftables.conf. Sets out and rc.
boot_with_tool() {
  local offered=$1
  : >"${stubs}/calls"
  out="$(
    export PATH="${stubs}:${PATH}"
    work="$(mktemp -d)"
    installed() { return 0; }
    mds() { return 22; }
    mds_file() {
      case "$1" in
        */watchtower-ruleset) [[ "$offered" != none ]] && cp "$offered" "$2" ;;
        */watchtower-nftables) cp "${rules}/a" "$2" ;;
        *) return 22 ;;
      esac
    }
    guard 2>&1
  )"
  rc=$?
}

# A new tool that passes, on a first install: in, and sshd up through it. Not the last
# good copy while its trial is pending (the review's fix, 2026-11-04): it hasn't yet
# run that trial's confirmation or rollback. A boot after the trial keeps it.
tool_as "${variants}/older" none
boot_with_tool ruleset.sh
check "tool, a new one that passes: the boot goes on" reason_is 0
check "tool, a new one that passes: in place" same_file ruleset.sh "$real_tool"
check "tool, a new one that passes: sshd, through it" no_file "${stubs}/sshd-down"
refute "tool, a new one that passes: no fallback" said 'falling back'
check "tool, a new one that passes, its trial pending: not kept yet" no_file "$last_good"
check "tool, a new one that passes, its trial pending: says so" said 'a ruleset trial is pending'
confirm
reboot_vm
touch "${stubs}/sshd-down"
boot_with_tool ruleset.sh
check "tool, a new one that passes, a boot after its trial: the boot goes on" reason_is 0
check "tool, a new one that passes, a boot after its trial: kept as the last good copy" same_file ruleset.sh "$last_good"

# One whose apply ends at once, says all is well and starts nothing: passes the
# self-check, and is never kept over a good last good copy.
tool_as ruleset.sh ruleset.sh settled
boot_with_tool "${variants}/apply-zero"
check "tool, apply-zero: the boot goes on" reason_is 0
check "tool, apply-zero: sshd never came up" test -e "${stubs}/sshd-down"
check "tool, apply-zero: the last good copy stays the good one" same_file ruleset.sh "$last_good"
check "tool, apply-zero: says why" said "apply didn't end with its ruleset confirmed at this boot"
# ... and as a real boot leaves things (the review's case, 2026-11-04): sshd already up
# through the tool before's gate, and the guard loaded at early boot, with no trial, as
# a run that changes only ruleset.sh has. Neither is the new tool's doing, so neither
# keeps it.
tool_as ruleset.sh ruleset.sh settled
rm -f "${stubs}/sshd-down"
boot_with_tool "${variants}/apply-zero"
check "tool, apply-zero, sshd up from the boot: the boot goes on" reason_is 0
refute "tool, apply-zero, sshd up from the boot: it started nothing" called "start ssh.service"
check "tool, apply-zero, sshd up from the boot: the last good copy stays the good one" same_file ruleset.sh "$last_good"
check "tool, apply-zero, sshd up from the boot: says why" said "apply didn't end with its ruleset confirmed at this boot"
# ... while the good tool, at a boot like that, is kept: its apply says confirmed.
tool_as "${variants}/older" "${variants}/older" settled
rm -f "${stubs}/sshd-down"
boot_with_tool ruleset.sh
check "tool, a good one, sshd up from the boot, no trial: kept" same_file ruleset.sh "$last_good"

# What a boot must show before the tool is kept, beyond its self-check.
# promote_case <name> <sshd: up|down> <guard: on|off> <account: yes|no>
#   <trial pending: yes|no> <want: kept|not> [<this boot's ruleset word, or none>]
promote_case() {
  local name=$1 sshd=$2 guard=$3 account=$4 pending=$5 want=$6 word=${7:-confirmed} dir got result
  dir="$(mktemp -d)"
  install -m 0755 ruleset.sh "${dir}/tool"
  install -m 0755 "${variants}/older" "${dir}/last-good"
  got="$(
    export PATH="${stubs}:${PATH}"
    work="$(mktemp -d)"
    RULESET_TOOL="${dir}/tool"
    TOOL_LAST_GOOD="${dir}/last-good"
    PENDING_TRIAL="${dir}/pending"
    RULESET_WORD="${dir}/word"
    [[ "$pending" != yes ]] || touch "$PENDING_TRIAL"
    [[ "$word" == none ]] || printf '%s\n' "$word" >"$RULESET_WORD"
    systemctl() { [[ "$*" == "is-active --quiet ssh.service" && "$sshd" == up ]]; }
    guard_loaded() { [[ "$guard" == on ]]; }
    get() { if [[ "$account" == no ]]; then echo 404; else echo 200; fi; }
    promote_tool 2>&1
  )"
  if cmp -s "${dir}/tool" "${dir}/last-good"; then result=kept; else result=not; fi
  if [[ "$result" == "$want" ]]; then pass "tool, promotion: ${name}: ${want}"; else flunk "tool, promotion: ${name}: ${result}: ${got//$'\n'/ }"; fi
}
promote_case "sshd up, the guard on, no trial" up on yes no kept
promote_case "sshd up, no guard, no account so no token" up off no no kept
promote_case "sshd up, no guard, an account" up off yes no not
promote_case "sshd down" down on yes no not
promote_case "a trial pending, over a last good copy" up on yes yes not
promote_case "all well but the apply said nothing at this boot" up on yes no not none
promote_case "all well but the apply said pending at this boot" up on yes no not pending

# Each bug the self-check sees: not put in place, the last good copy untouched, and why.
# self_check_case <variant> <what it says>
self_check_case() {
  tool_as ruleset.sh ruleset.sh
  boot_with_tool "${variants}/$1"
  check "tool, $1: the boot goes on, on the old tool" reason_is 0
  check "tool, $1: not put in place" same_file ruleset.sh "$real_tool"
  check "tool, $1: the last good copy untouched" same_file ruleset.sh "$last_good"
  check "tool, $1: says it failed its self-check" said 'failed its self-check'
  check "tool, $1: says why: $2" said "$2"
}
self_check_case gate-yes 'its gate lets sshd run with no guard'
self_check_case loaded-yes 'it takes an empty ruleset for a guard'
self_check_case floor-open "its floor doesn't guard"
self_check_case floor-broken "its floor doesn't pass nft --check"
self_check_case cut-short 'is cut short or won'
self_check_case gate-no 'its gate keeps sshd down with its floor on'

# The real first install: no account, and the self-check's namespace has no way to the
# metadata server (curl gets nothing there, as on the VM), so its gate must still keep
# sshd down with no guard, and a correct tool passes. Nothing it loads, and nothing it
# puts on lo, reaches the live namespace.
tool_as "${variants}/older" none
echo 404 >"${stubs}/account-code"
metadata_on_lo=""
ip -4 addr show dev lo | grep -q '169\.254\.169\.254' && metadata_on_lo=1
ip addr del 169.254.169.254/32 dev lo 2>/dev/null
nft --file "${rules}/marked"
live_ruleset_before="$(nft list ruleset)"
live_lo_before="$(ip -o addr show dev lo)"
# Executable, as take_tool makes a tool before it's checked.
install -m 0700 ruleset.sh /tmp/tool-to-check
self_check_out="$(
  export PATH="${stubs}:${PATH}"
  work="$(mktemp -d)"
  tool_self_check /tmp/tool-to-check 2>&1
)"
self_check_rc=$?
check "tool, self-check with no account: a correct tool passes" test "$self_check_rc" = 0
check "tool, self-check: the live ruleset is as it was" test "$(nft list ruleset)" = "$live_ruleset_before"
check "tool, self-check: the live lo is as it was" test "$(ip -o addr show dev lo)" = "$live_lo_before"
refute "tool, self-check: no metadata address left on the live lo" grep -q '169\.254\.169\.254' <<<"$(ip -4 addr show dev lo)"
[[ "$self_check_rc" == 0 ]] || echo "      self-check said: ${self_check_out//$'\n'/ }"
# The same with nothing in the live kernel and a VM with an account, where a self-check
# run in the live namespace would get as far as loading its floor and putting the
# metadata server's address on lo (as the review saw): it must leave both as they were.
nft flush ruleset
echo 200 >"${stubs}/account-code"
live_ruleset_before="$(nft list ruleset)"
live_lo_before="$(ip -o addr show dev lo)"
(
  export PATH="${stubs}:${PATH}"
  work="$(mktemp -d)"
  tool_self_check /tmp/tool-to-check >/dev/null 2>&1
)
self_check_rc=$?
check "tool, self-check from an empty kernel: a correct tool passes" test "$self_check_rc" = 0
check "tool, self-check from an empty kernel: the live ruleset is still empty" test "$(nft list ruleset)" = "$live_ruleset_before"
check "tool, self-check from an empty kernel: the live lo is as it was" test "$(ip -o addr show dev lo)" = "$live_lo_before"
[[ -z "$metadata_on_lo" ]] || ip addr add 169.254.169.254/32 dev lo 2>/dev/null
# ... and so, at a first install's boot, the new tool goes in.
tool_as "${variants}/older" none
echo 404 >"${stubs}/account-code"
boot_with_tool ruleset.sh
check "tool, no account (a first install): a new one that passes goes in" same_file ruleset.sh "$real_tool"
check "tool, no account (a first install): the boot goes on" reason_is 0

# An apply that hangs, holding the lock the rollback needs: stopped after TOOL_TIMEOUT
# (here 3s), with all it started, and the last good copy has the boot, through the same
# lock.
tool_timeout_before="$TOOL_TIMEOUT"
TOOL_TIMEOUT=3s
tool_as ruleset.sh ruleset.sh settled
boot_with_tool "${variants}/apply-hangs"
TOOL_TIMEOUT="$tool_timeout_before"
check "tool, apply hangs: says it was stopped" said 'apply took longer than 3s, and was stopped'
check "tool, apply hangs: falls back" said 'falling back to its last good copy'
check "tool, apply hangs: the boot goes on" reason_is 0
check "tool, apply hangs: sshd up, through the last good copy" no_file "${stubs}/sshd-down"
# No pgrep in this image: the processes' own command lines.
hung_sleep_left() {
  local cmdline
  for cmdline in /proc/[0-9]*/cmdline; do
    [[ "$(tr '\0' ' ' <"$cmdline" 2>/dev/null)" != "sleep 1000 " ]] || return 0
  done
  return 1
}
refute "tool, apply hangs: nothing of it left running" hung_sleep_left

# Passes its self-check, and fails at the boot: the last good copy has the boot instead.
tool_as ruleset.sh ruleset.sh
boot_with_tool "${variants}/apply-fails"
check "tool, fails at the boot: falls back" said 'falling back to its last good copy'
check "tool, fails at the boot: the boot goes on" reason_is 0
check "tool, fails at the boot: the last good copy in its place" same_file ruleset.sh "$real_tool"
check "tool, fails at the boot: sshd, through the last good copy" called "start ssh.service"
check "tool, fails at the boot: the last good copy stays what it was" same_file ruleset.sh "$last_good"
check "tool, fails at the boot: the guard is on" guard_on
# ... with no last good copy: the boot stops there, and nothing starts sshd.
tool_as "${variants}/older" none
boot_with_tool "${variants}/apply-fails"
check "tool, fails at the boot, no last good copy: stops" reason_is 1
refute "tool, fails at the boot, no last good copy: nothing starts sshd" called "start ssh.service"
check "tool, fails at the boot, no last good copy: none made of it" no_file "$last_good"

# The tool gone: its last good copy comes back, with metadata silent.
tool_as none ruleset.sh
boot_with_tool none
check "tool, gone: its last good copy back" same_file ruleset.sh "$real_tool"
check "tool, gone: says so" said 'putting back its last good copy'
check "tool, gone: the boot goes on" reason_is 0
check "tool, gone: sshd, through it" called "start ssh.service"
# ... and with none, and metadata's failing its self-check: never in, even as the only one.
tool_as none none
boot_with_tool "${variants}/gate-yes"
check "tool, gone, metadata's fails: stops" reason_is 1
check "tool, gone, metadata's fails: not put in place" no_file "$real_tool"
refute "tool, gone, metadata's fails: nothing starts sshd" called "start ssh.service"
check "tool, gone, metadata's fails: says sshd stays as the boot left it" said 'it stays as the boot left it'
# ... with sshd's drop-in gone too, so sshd up from the boot, ungated, with no guard, on
# a VM with an account: stopped before the boot stops, as recovery.sh does (the review's
# fix, 2026-11-04).
tool_as none none
rm -f "${stubs}/sshd-down" "${stubs}/sshd-runs-its-gate"
touch "${stubs}/sshd-ungated"
boot_with_tool none
check "tool, gone, sshd up ungated with no guard and an account: the boot stops" reason_is 1
check "tool, gone, sshd up ungated with no guard and an account: stopped" called "stop ssh.service"
check "tool, gone, sshd up ungated with no guard and an account: sshd down" test -e "${stubs}/sshd-down"
check "tool, gone, sshd up ungated with no guard and an account: says why" said 'sshd is up with no guard, on a VM that may have an account: stopping it'
# ... and left up on a VM with no account, so no token to guard.
tool_as none none
rm -f "${stubs}/sshd-down" "${stubs}/sshd-runs-its-gate"
touch "${stubs}/sshd-ungated"
echo 404 >"${stubs}/account-code"
boot_with_tool none
refute "tool, gone, sshd up ungated, no account: left up" called "stop ssh.service"
check "tool, gone, sshd up ungated, no account: up" no_file "${stubs}/sshd-down"
# The check itself is the same in startup.sh and recovery.sh, word for word.
unguarded_in_startup="$(sed -n '/^sshd_up_unguarded() {$/,/^}$/p' startup.sh)"
check "sshd_up_unguarded: in startup.sh" test -n "$unguarded_in_startup"
check "sshd_up_unguarded: the same in recovery.sh" test "$(sed -n '/^sshd_up_unguarded() {$/,/^}$/p' recovery.sh)" = "$unguarded_in_startup"

# A tool on disk that never passed the self-check is never kept, though it brought sshd up
# at a boot with no trial.
tool_as "${variants}/gate-yes" ruleset.sh settled
boot_with_tool none
check "tool, never checked: the boot goes on" reason_is 0
check "tool, never checked: not kept as the last good copy" same_file ruleset.sh "$last_good"
check "tool, never checked: says so" said "isn't kept as the last good copy"

# Back as the rest expects it.
fresh
rm -f "$last_good"
install -m 0755 ruleset.sh "$real_tool"
echo 404 >"${stubs}/account-code"

# --- recovery: recovery.sh, the one-off startup script for when SSH is gone -------
recovery_bin="${stubs}/recovery-bin"
mkdir -p "$recovery_bin"
chmod 0755 "$recovery_bin"
# df says what /stubs/disk-percent holds, and vacuuming the journal is what frees
# the room, when /stubs/disk-frees says it's to, and with that the install works.
cat >"${recovery_bin}/df" <<'STUB'
#!/bin/bash
echo 'Use%'
cat /stubs/disk-percent
STUB
cat >"${recovery_bin}/journalctl" <<'STUB'
#!/bin/bash
echo "journalctl $*" >>/stubs/calls
if [[ "$*" == *--vacuum-size=* && -e /stubs/disk-frees ]]; then
  echo ' 58%' >/stubs/disk-percent
  rm -f /stubs/install-broken
fi
exit 0
STUB
cat >"${recovery_bin}/apt-get" <<'STUB'
#!/bin/bash
echo "apt-get $*" >>/stubs/calls
STUB
cat >"${recovery_bin}/dpkg" <<'STUB'
#!/bin/bash
echo "dpkg $*" >>/stubs/calls
STUB
cat >"${recovery_bin}/du" <<'STUB'
#!/bin/bash
echo '9.0G /home/stand-in-user'
STUB
# Metadata's copy of the tool, when /stubs/tool-in-metadata is there.
cat >"${recovery_bin}/curl" <<'STUB'
#!/bin/bash
if [[ "$*" == *instance/attributes/watchtower-ruleset* ]]; then
  [[ -e /stubs/tool-in-metadata ]] || exit 22
  # By name only: on stdout a retry leaves a part in front of the whole.
  args=("$@")
  for ((i = 0; i < $#; i++)); do
    if [[ "${args[i]}" == -o ]]; then
      cp /stubs/tool-in-metadata "${args[i + 1]}"
      exit 0
    fi
  done
  exit 99
fi
exec /stubs/curl "$@"
STUB
chmod 0755 "${recovery_bin}/df" "${recovery_bin}/journalctl" "${recovery_bin}/apt-get" "${recovery_bin}/dpkg" "${recovery_bin}/du" "${recovery_bin}/curl"
recovery() {
  out="$(PATH="${recovery_bin}:${stubs}:${PATH}" bash /check/recovery.sh 2>&1)"
  rc=$?
}
# fixture_files: what it may remove, and what it never may.
fixture_files() {
  mkdir -p /var/lib/alloy/data/wal /home/stand-in-user
  touch /var/lib/alloy/data/wal/000001 /home/stand-in-user/a-file /var/log/stand-in.log /var/log/stand-in.log.1 /var/log/stand-in.log.2.gz
}
full_disk() { echo "$1%" | sed 's/^/ /' >"${stubs}/disk-percent"; }
rm -f "${stubs}/disk-frees"

# Healthy: it changes nothing.
fresh
apply_ruleset a
confirm
fixture_files
full_disk 41
: >"${stubs}/calls"
recovery
check "recovery, healthy: exit 0" reason_is 0
check "recovery, healthy: says not full" said 'not full: removing nothing'
check "recovery, healthy: done" said 'bastion-recovery: done'
check "recovery, healthy: the guard" said 'bastion-recovery: guard: loaded'
check "recovery, healthy: sshd" said 'bastion-recovery: sshd: active'
check "recovery, healthy: an old log stays" test -e /var/log/stand-in.log.1
check "recovery, healthy: Alloy's buffer stays" test -e /var/lib/alloy/data/wal/000001
refute "recovery, healthy: apt's cache stays" called "apt-get clean"
refute "recovery, healthy: no reboot" called "--no-block reboot"
check "recovery, healthy: the ruleset stays" same_file "${rules}/a" /etc/nftables.conf
check "recovery, healthy: still confirmed" test -z "$(cat "${state_dir}/pending" 2>/dev/null)"

# Full, with a rollback the disk held up: room, and then the rollback finishes.
fresh
apply_ruleset a
touch "${stubs}/install-broken"
fire
check "recovery, full disk: the rollback is stuck" state_is "$sha_a" failed
check "recovery, full disk: on its record" test -e "${state_dir}/pending"
fixture_files
full_disk 100
touch "${stubs}/disk-frees"
: >"${stubs}/calls"
recovery
rm -f "${stubs}/disk-frees"
check "recovery, full disk: exit 0" reason_is 0
check "recovery, full disk: apt's cache goes" called "apt-get clean"
check "recovery, full disk: the journal's trimmed" called "journalctl --vacuum-size=64M"
refute "recovery, full disk: an old log goes" test -e /var/log/stand-in.log.1
refute "recovery, full disk: and a gzipped one" test -e /var/log/stand-in.log.2.gz
check "recovery, full disk: today's log stays" test -e /var/log/stand-in.log
check "recovery, full disk: a user's file stays" test -e /home/stand-in-user/a-file
check "recovery, full disk: enough room, so Alloy's buffer stays" test -e /var/lib/alloy/data/wal/000001
check "recovery, full disk: the rollback finishes" state_is "$sha_a" "rolled back"
check "recovery, full disk: the old ruleset back on disk" same_file "${rules}/package" /etc/nftables.conf
refute "recovery, full disk: off the record" test -e "${state_dir}/pending"
check "recovery, full disk: and it reboots" called "--no-block reboot"
check "recovery, full disk: says it will run again" said 'this script runs once more'
# The boot after it.
reboot_vm
full_disk 58
recovery
check "recovery, the next boot: exit 0" reason_is 0
check "recovery, the next boot: done" said 'bastion-recovery: done'
refute "recovery, the next boot: no reboot, so no loop" called "--no-block reboot"
check "recovery, the next boot: the guard, from the floor" said 'bastion-recovery: guard: loaded'
check "recovery, the next boot: sshd" called "start ssh.service"

# Too full for that: Alloy's buffer goes, and it names what's left to you.
fresh
apply_ruleset a
confirm
fixture_files
full_disk 100
: >"${stubs}/calls"
recovery
check "recovery, still full: exit 0" reason_is 0
refute "recovery, still full: Alloy's buffer goes" test -e /var/lib/alloy/data/wal/000001
check "recovery, still full: its directory stays" test -d /var/lib/alloy/data
check "recovery, still full: a user's file stays" test -e /home/stand-in-user/a-file
check "recovery, still full: Alloy back up" called "start alloy.service"
check "recovery, still full: the largest paths" said '/home/stand-in-user'
check "recovery, still full: sshd still asked for" called "start ssh.service"
check "recovery, still full: done" said 'bastion-recovery: done'

# nft loads nothing, on a VM with an account: reinstalled once, and then it says so.
fresh
full_disk 41
echo 200 >"${stubs}/account-code"
touch "${stubs}/nft-broken" "${stubs}/sshd-down"
: >"${stubs}/calls"
recovery
rm -f "${stubs}/nft-broken" "${stubs}/sshd-down"
echo 404 >"${stubs}/account-code"
check "recovery, nft broken: exit 0" reason_is 0
check "recovery, nft broken: reinstalls it" called "apt-get -q -o DPkg::Lock::Timeout=120 install -y --reinstall --no-install-recommends nftables"
check "recovery, nft broken: with fresh lists" test "$(line_of 'apt-get -q -o DPkg::Lock::Timeout=120 update')" -lt "$(line_of 'apt-get -q -o DPkg::Lock::Timeout=120 install -y --reinstall --no-install-recommends nftables')"
refute "recovery, nft broken: the gate holds, so no sshd" called "start ssh.service"
check "recovery, nft broken: says the guard's off" said 'bastion-recovery: guard: NOT loaded'
check "recovery, nft broken: says sshd's off" said 'bastion-recovery: sshd: NOT active'
check "recovery, nft broken: says why" said "why sshd isn't up"
check "recovery, nft broken: done" said 'bastion-recovery: done'

# The tool gone or cut short, with sshd as it really is: nothing without its gate,
# on a VM with an account and the guard in the kernel.
real_tool=/usr/local/sbin/watchtower-ruleset
# tool_damage <how>: gone, cut mid-line, or cut at a line, where it still parses.
tool_damage() {
  case "$1" in
    gone) rm -f "$real_tool" ;;
    mid-line) head -c 12000 ruleset.sh >"$real_tool" ;;
    at-a-line) head -n 40 ruleset.sh >"$real_tool" ;;
  esac
  [[ "$1" == gone ]] || chmod 0755 "$real_tool"
}
tool_setting() {
  fresh
  full_disk 41
  install -m 0755 ruleset.sh "$real_tool"
  rm -f "$last_good"
  nft --file nftables.conf
  echo 200 >"${stubs}/account-code"
  touch "${stubs}/sshd-runs-its-gate" "${stubs}/sshd-down"
  rm -f "${stubs}/tool-in-metadata"
  : >"${stubs}/calls"
}
for damage in gone mid-line at-a-line; do
  # Nothing in metadata: sshd stays down, and says so. It isn't got past the gate.
  tool_setting
  tool_damage "$damage"
  recovery
  check "recovery, tool ${damage}, nothing in metadata: exit 0" reason_is 0
  check "recovery, tool ${damage}, nothing in metadata: says it couldn't" said 'could not restore it'
  if [[ "$damage" != at-a-line ]]; then
    check "recovery, tool ${damage}, nothing in metadata: says sshd is down" said 'bastion-recovery: sshd: NOT active'
    check "recovery, tool ${damage}, nothing in metadata: sshd is down" test -e "${stubs}/sshd-down"
  fi
  # Not even through sshd's own gate: with no tool, sshd isn't asked for at all.
  refute "recovery, tool ${damage}, nothing in metadata: never asks for sshd" called "start ssh.service"
  check "recovery, tool ${damage}, nothing in metadata: says it won't" said 'not asking for sshd'
  check "recovery, tool ${damage}, nothing in metadata: done" said 'bastion-recovery: done'
  # A good copy there: it's back, and sshd with it.
  tool_setting
  tool_damage "$damage"
  cp ruleset.sh "${stubs}/tool-in-metadata"
  recovery
  check "recovery, tool ${damage}, metadata has it: exit 0" reason_is 0
  check "recovery, tool ${damage}, metadata has it: says so" said 'restored it'
  check "recovery, tool ${damage}, metadata has it: whole" same_file ruleset.sh "$real_tool"
  check "recovery, tool ${damage}, metadata has it: executable" test -x "$real_tool"
  check "recovery, tool ${damage}, metadata has it: sshd up" said 'bastion-recovery: sshd: active'
  check "recovery, tool ${damage}, metadata has it: through the gate" no_file "${stubs}/sshd-down"
done
# A bad copy there: not put in place, and no temp file left.
tool_setting
tool_damage mid-line
cp "$real_tool" "${stubs}/damaged-tool"
head -c 9000 ruleset.sh >"${stubs}/tool-in-metadata"
recovery
check "recovery, a bad copy in metadata: not put in place" same_file "${stubs}/damaged-tool" "$real_tool"
check "recovery, a bad copy in metadata: nothing left behind" no_file "${real_tool}.tmp"
check "recovery, a bad copy in metadata: says it couldn't" said 'could not restore it'
# No tool, and sshd's drop-in gone too (the owner's decision, 2026-11-04). At a real boot
# systemd has started sshd before any startup script, and with no drop-in nothing gated
# it: so sshd is up here, with no guard, on a VM with an account. Never asked for, and
# stopped (the review's fix, 2026-11-04).
tool_setting
tool_damage gone
rm -f "${stubs}/sshd-runs-its-gate" "${stubs}/sshd-down"
touch "${stubs}/sshd-ungated"
nft flush ruleset
recovery
refute "recovery, no tool and no gate on sshd: never asks for sshd" called "start ssh.service"
check "recovery, no tool and no gate on sshd, up from the boot with no guard: stopped" called "stop ssh.service"
check "recovery, no tool and no gate on sshd: sshd down" test -e "${stubs}/sshd-down"
check "recovery, no tool and no gate on sshd: says why it stopped it" said 'sshd is up with no guard, on a VM that may have an account: stopping it'
check "recovery, no tool and no gate on sshd: says so" said 'bastion-recovery: sshd: NOT active'
# ... left up with the guard there, by its name, as there's no tool to ask by its rules.
tool_setting
tool_damage gone
rm -f "${stubs}/sshd-runs-its-gate" "${stubs}/sshd-down"
touch "${stubs}/sshd-ungated"
recovery
refute "recovery, no tool, no gate on sshd, the guard there: left up" called "stop ssh.service"
check "recovery, no tool, no gate on sshd, the guard there: up" no_file "${stubs}/sshd-down"
# ... and on a VM with no account, so no token to guard.
tool_setting
tool_damage gone
rm -f "${stubs}/sshd-runs-its-gate" "${stubs}/sshd-down"
touch "${stubs}/sshd-ungated"
echo 404 >"${stubs}/account-code"
nft flush ruleset
recovery
refute "recovery, no tool, no gate on sshd, no account: left up" called "stop ssh.service"
check "recovery, no tool, no gate on sshd, no account: up" no_file "${stubs}/sshd-down"
# The last good copy, with nothing in metadata: back, and sshd through its gate.
tool_setting
tool_damage gone
install -m 0755 ruleset.sh "$last_good"
recovery
check "recovery, tool gone, a last good copy: says so" said 'restored it from its last good copy'
check "recovery, tool gone, a last good copy: whole" same_file ruleset.sh "$real_tool"
check "recovery, tool gone, a last good copy: sshd up, through the gate" no_file "${stubs}/sshd-down"
# A tool that fails, with a last good copy: that copy takes its place, and is asked.
tool_setting
install -m 0755 "${variants}/apply-fails" "$real_tool"
install -m 0755 ruleset.sh "$last_good"
recovery
check "recovery, a tool that fails: falls back" said 'falling back to its last good copy'
check "recovery, a tool that fails: the last good copy in its place" same_file ruleset.sh "$real_tool"
check "recovery, a tool that fails: sets its units up again, as at a boot" called "enable --quiet nftables.service ${timer} watchtower-ruleset-confirm.path"
check "recovery, a tool that fails: sshd up, through the gate" no_file "${stubs}/sshd-down"
# A tool whose apply hangs: stopped after TOOL_TIMEOUT (3s in a copy of the script),
# and its last good copy takes over, through the same lock.
sed 's/^TOOL_TIMEOUT="5m"$/TOOL_TIMEOUT="3s"/' recovery.sh >/check/recovery-short.sh
tool_setting
install -m 0755 "${variants}/apply-hangs" "$real_tool"
install -m 0755 ruleset.sh "$last_good"
out="$(PATH="${recovery_bin}:${stubs}:${PATH}" bash /check/recovery-short.sh 2>&1)"
rc=$?
check "recovery, apply hangs: the copy has the short limit" grep -qx 'TOOL_TIMEOUT="3s"' /check/recovery-short.sh
check "recovery, apply hangs: says it was stopped" said 'apply took longer than 3s, and was stopped'
check "recovery, apply hangs: falls back" said 'falling back to its last good copy'
check "recovery, apply hangs: sshd up, through the gate" no_file "${stubs}/sshd-down"
refute "recovery, apply hangs: nothing of it left running" hung_sleep_left
# ... and with none: sshd stays down.
tool_setting
install -m 0755 "${variants}/apply-fails" "$real_tool"
recovery
check "recovery, a tool that fails, no last good copy: sshd stays down" test -e "${stubs}/sshd-down"
# A copy in metadata that's whole and fails the self-check: never goes in.
tool_setting
tool_damage gone
cp "${variants}/gate-yes" "${stubs}/tool-in-metadata"
recovery
check "recovery, metadata's copy fails its self-check: not put in place" no_file "$real_tool"
check "recovery, metadata's copy fails its self-check: says why" said 'its gate lets sshd run with no guard'
refute "recovery, metadata's copy fails its self-check: never asks for sshd" called "start ssh.service"
check "recovery, metadata's copy fails its self-check: sshd stays down" test -e "${stubs}/sshd-down"
# The gate, untouched by any of it: guard off, an account, a whole tool.
tool_setting
nft flush ruleset
touch "${stubs}/nft-broken"
recovery
rm -f "${stubs}/nft-broken"
check "recovery, no guard: sshd stays down" test -e "${stubs}/sshd-down"
install -m 0755 ruleset.sh "$real_tool"
fresh
echo 404 >"${stubs}/account-code"

# --- a real full disk: a small tmpfs, real install, real ENOSPC ------------------
# put, from startup.sh, over a tool on a disk with no room: the old one stays whole.
tiny=/tiny-disk
mkdir -p "$tiny"
if mount -t tmpfs -o size=64k tmpfs "$tiny"; then
  head -c 30000 /dev/zero >"${tiny}/filler"
  { echo '#!/bin/bash'; head -c 28000 /dev/zero | tr '\0' '#'; echo; echo 'main "$@"'; } >"${tiny}/tool"
  chmod 0755 "${tiny}/tool"
  cp "${tiny}/tool" /tmp/tool-before
  { echo '#!/bin/bash'; head -c 40000 /dev/zero | tr '\0' '#'; echo; } >/tmp/tool-bigger
  (put /tmp/tool-bigger "${tiny}/tool" 0755 root) 2>/dev/null
  rc=$?
  check "put, no room: fails" test "$rc" = 1
  check "put, no room: the tool stays whole" same_file /tmp/tool-before "${tiny}/tool"
  check "put, no room: nothing left behind" no_file "${tiny}/tool.tmp"
  rm -f "${tiny}/filler"
  # Room, and a tool that won't parse: the old one stays too.
  printf '#!/bin/bash\nif then\n' >/tmp/tool-broken
  (put /tmp/tool-broken "${tiny}/tool" 0755 root) 2>/dev/null
  check "put, won't parse: the tool stays whole" same_file /tmp/tool-before "${tiny}/tool"
  check "put, won't parse: nothing left behind" no_file "${tiny}/tool.tmp"
  # Room, and a good one: it goes in, with its mode.
  printf '#!/bin/bash\necho new\n' >/tmp/tool-good
  (put /tmp/tool-good "${tiny}/tool" 0755 root) 2>/dev/null
  check "put, room: in place" same_file /tmp/tool-good "${tiny}/tool"
  check "put, room: executable" test -x "${tiny}/tool"
  # A file that's no script needn't parse.
  printf 'not ( a script\n' >/tmp/a-config
  (put /tmp/a-config "${tiny}/config" 0644 root) 2>/dev/null
  check "put, a config: in place" same_file /tmp/a-config "${tiny}/config"
  umount "$tiny"
else
  flunk "a real full disk: can't mount a small tmpfs here"
fi

# The switch itself, with its ruleset and state on that small disk.
small_tool=/small-disk-ruleset.sh
if mount -t tmpfs -o size=64k tmpfs "$tiny"; then
  sed -e "s#^STATE=.*#STATE=\"${tiny}/state\"#" -e "s#^RULESET=.*#RULESET=\"${tiny}/nftables.conf\"#" ruleset.sh >"$small_tool"
  small() { PATH="${stubs}:${PATH}" bash "$small_tool" "$@"; }
  fill_disk() { head -c 100000 /dev/zero >"${tiny}/filler" 2>/dev/null; }
  fresh
  echo "${tiny}/nftables.conf" >"${stubs}/ruleset-path"
  cp "${rules}/marked" "${tiny}/nftables.conf"
  nft --file "${rules}/marked"
  # A login on a full disk: not lost. It counts once there's room.
  : >"${stubs}/attribute"
  out="$(small apply "${rules}/a" "" 2>&1)"; rc=$?
  check "full disk: a on trial" state_is "$sha_a" pending
  fill_disk
  touch "${dropbox}/confirm-${login_a}"
  out="$(small confirm 2>&1)"; rc=$?
  check "full disk, a login: its file stays" test -e "${dropbox}/confirm-${login_a}"
  check "full disk, a login: the trial stands" grep -qx "$sha_a" "${tiny}/state/pending"
  refute "full disk, a login: not confirmed" state_is "$sha_a" confirmed
  check "full disk, a login: says so" said 'could not record the confirmation'
  check "full disk, a login: still shows a login of this run got in" login_seen "$this_boot" "$run_a" "$login_a" <"${stubs}/attribute-login"
  rm -f "${tiny}/filler"
  out="$(small confirm 2>&1)"; rc=$?
  check "full disk, then room: confirmed" state_is "$sha_a" confirmed
  check "full disk, then room: its file went" no_file "${dropbox}/confirm-${login_a}"
  check "full disk, then room: nothing pending" no_file "${tiny}/state/pending"
  # A rollback on a full disk, by real ENOSPC.
  : >"${stubs}/attribute"
  out="$(small apply "${rules}/b" "" 2>&1)"; rc=$?
  check "full disk, rollback: b on trial" state_is "$sha_b" pending
  fill_disk
  : >"${stubs}/calls"
  out="$(small rollback 2>&1)"; rc=$?
  refute "full disk, rollback: fails, so it retries" reason_is 0
  check "full disk, rollback: says failed" state_is "$sha_b" failed
  check "full disk, rollback: the old guard is in the kernel, needing no disk" guard_on
  check "full disk, rollback: the record stays" grep -qx "$sha_b" "${tiny}/state/pending"
  check "full disk, rollback: the file is whole" same_file "${rules}/b" "${tiny}/nftables.conf"
  refute "full disk, rollback: no reboot" called "--no-block reboot"
  rm -f "${tiny}/filler"
  out="$(small rollback 2>&1)"; rc=$?
  check "full disk, rollback, then room: exit 0" reason_is 0
  check "full disk, rollback, then room: says rolled back" state_is "$sha_b" "rolled back"
  check "full disk, rollback, then room: the old one back" same_file "${rules}/a" "${tiny}/nftables.conf"
  check "full disk, rollback, then room: reboots" called "--no-block reboot"
  umount "$tiny"
  rm -f "${stubs}/ruleset-path"
else
  flunk "a real full disk: can't mount a small tmpfs here"
fi
exit "$fail"
RUN

# SYS_ADMIN for the throwaway network namespace ruleset.sh tries a file in, which
# real root on the VM has anyway.
cid="$("$rt" create --memory 3g --cap-add NET_ADMIN --cap-add SYS_ADMIN "$DEBIAN_IMAGE" bash /check/run.sh)"
"$rt" cp "${work}/." "${cid}:/check"
"$rt" start -a "$cid"
