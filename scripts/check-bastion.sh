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
#   fetch  only a missing or empty secret takes telemetry down: any other
#          failure to read it, and a config that fails its checks, leave the
#          tunnel and Alloy as they are.
#   guard  nftables.conf checked, loaded twice (a reload, as at boot), and
#          probed on 169.254.169.254 (on lo): root reaches it over HTTP,
#          other uids are refused at once, and every uid still reaches its
#          DNS (53), DHCP (67) and NTP (123), and everything else. The same
#          on its IPv6 address, fd20:ce::254, where the container has IPv6.
#   ruleset  ruleset.sh's dead man's switch, on real nft with systemctl and the
#          metadata server stubbed: arm, confirm, fire, rejected, re-arm after
#          a reboot, first install, a retry, a guard that won't load, what a
#          non-root user can do, and the lines bootstrap.sh reads, through its
#          own ruleset_state. Its units are checked by systemd-analyze verify.
#
#   scripts/check-bastion.sh            # docker; CONTAINER_RUNTIME=podman locally
#
# A container has no systemd running and no GCE, so only the real VM can show:
# that the path unit and the timer fire (at the 10 minutes, and again after a
# reboot), that a login's file reaches confirm, that the two services' lines
# reach the serial console, that sshd's drop-in holds it back and the guest
# agent's restarts get past it, that a package upgrade's restart keeps both up,
# that the metadata server says 404 for a VM with no account, and that the
# real rollback reboots into the old ruleset.
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

cp "${repo_root}/config/bastion/startup.sh" "${repo_root}/config/bastion/nftables.conf" "${repo_root}/config/bastion/ruleset.sh" "$work/"
# The line bootstrap.sh stops the VM on, which run.sh checks main prints.
grep -qF "grep -cF 'bastion: settled'" "${repo_root}/scripts/bootstrap.sh" || {
  echo "FAIL  bootstrap.sh doesn't wait for 'bastion: settled'"
  exit 1
}
# How bootstrap.sh reads the ruleset's lines, which run.sh checks ruleset.sh
# prints in that shape.
sed -n '/^ruleset_state() {$/,/^}$/p' "${repo_root}/scripts/bootstrap.sh" >"${work}/ruleset_state.sh"
[[ -s "${work}/ruleset_state.sh" ]] || {
  echo "FAIL  bootstrap.sh has no ruleset_state"
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
apt-get install -y -qq --no-install-recommends nftables python3 iproute2 systemd openssh-server >/dev/null

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
  updates() { echo updates; }
  guard() { echo guard; }
  guard_loaded() { return 0; }
  installed() { return 1; }
  apt_install() { echo apt; }
  fetch_peer() { peer_state=none; }
  teardown() { echo teardown; }
  main 2>/dev/null | tr '\n' ' '
)"
if [[ "$main_order" == "guard bastion: metadata guard loaded updates apt bastion: settled teardown " ]]; then
  pass "apt: main says settled only after the guard and apt, and the guard goes first"
else
  flunk "apt: main's order is: ${main_order}"
fi

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
    cat >"$RULESET_TOOL" <<TOOL
#!/bin/bash
[[ "\$1" == setup ]] && exit 0
shift
echo "args \${#}"
exit ${tool_rc}
TOOL
    chmod 0755 "$RULESET_TOOL"
    installed() { return 0; }
    mds() {
      case "$1" in
        */watchtower-nftables) [[ "$attribute" == yes ]] && echo ruleset ;;
        */watchtower-nftables-retry) [[ "$attribute" == yes ]] && echo 7 ;;
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
    [[ ! -e /stubs/load-broken ]] && nft --file /etc/nftables.conf 2>/dev/null ;;
  "restart watchtower-ruleset-rollback.timer")
    [[ ! -e /stubs/timer-broken ]] ;;
esac
STUB
cat >"${stubs}/curl" <<'STUB'
#!/bin/bash
cat /stubs/account-code
STUB
chmod 0755 "${stubs}/systemctl" "${stubs}/curl"

tool() { PATH="${stubs}:${PATH}" bash /check/ruleset.sh "$@"; }
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
state_is() { [[ "$(ruleset_state "$1" 0 <<<"$out")" == "$2" ]]; }
reason_is() { [[ "$rc" == "$1" ]]; }

# The files: a is the real one, b and c differ by a comment.
rules=/rulesets
mkdir -p "$rules"
cp nftables.conf "${rules}/a"
{ cat nftables.conf; echo '# b'; } >"${rules}/b"
{ cat nftables.conf; echo '# c'; } >"${rules}/c"
printf 'table inet metadata_guard {\n  this is not a ruleset\n}\n' >"${rules}/broken"
printf 'table inet other {\n}\n' >"${rules}/no-guard"
# Names the guard, so it passes the file's check, and doesn't define it.
printf '# chain metadata\ntable inet metadata_guard\ndelete table inet metadata_guard\ntable inet other {\n}\n' >"${rules}/fake-guard"
# What the package ships.
printf 'flush ruleset\ntable inet filter {\n  chain output {\n    type filter hook output priority filter;\n  }\n}\n' >"${rules}/package"
sha_a="$(sha256sum "${rules}/a" | cut -d' ' -f1)"
sha_b="$(sha256sum "${rules}/b" | cut -d' ' -f1)"
sha_c="$(sha256sum "${rules}/c" | cut -d' ' -f1)"
sha_fake="$(sha256sum "${rules}/fake-guard" | cut -d' ' -f1)"
sha_broken="$(sha256sum "${rules}/broken" | cut -d' ' -f1)"

# A bastion that has only ever had the package's ruleset, and no account.
fresh() {
  rm -rf "$state_dir" "$dropbox"
  rm -f "${stubs}/load-broken" "${stubs}/timer-broken"
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
  nft flush ruleset
  [[ ! -e "${stubs}/load-broken" && -f /etc/nftables.conf ]] && nft --file /etc/nftables.conf 2>/dev/null
  rm -rf "$dropbox"
  mkdir -p "$dropbox"
  chmod 1777 "$dropbox"
  : >"${stubs}/calls"
}
# apply_ruleset <file> [<retry>]: as startup.sh calls it. Sets out and rc.
apply_ruleset() {
  out="$(tool apply "${rules}/$1" "${2:-}" 2>&1)"
  rc=$?
}
fire() { out="$(tool rollback 2>&1)"; rc=$?; }
confirm() { out="$(tool confirm 2>&1)"; rc=$?; }

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
if [[ "$(grep -n "restart ${timer}" "${stubs}/calls" | cut -d: -f1)" -lt "$(grep -n 'reload-or-restart nftables.service' "${stubs}/calls" | cut -d: -f1)" ]]; then
  pass "ruleset: first install: armed before it loads"
else
  flunk "ruleset: first install: loaded before it armed"
fi
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
check "first install, rejected: sshd runs, as there's no token" called "start ssh.service"
check "first install, rejected: applied" reason_is 0

# Nothing runs with a token and no guard.
: >"${stubs}/calls"
echo 200 >"${stubs}/account-code"
out="$(tool gate 2>&1)"; rc=$?
refute "gate: refuses a VM with an account and no guard" reason_is 0
echo 000 >"${stubs}/account-code"
out="$(tool gate 2>&1)"; rc=$?
refute "gate: refuses when the metadata server doesn't answer" reason_is 0
echo 200 >"${stubs}/account-code"
apply_ruleset a
check "gate: apply exits 1 when sshd may not run" reason_is 1
check "gate: apply stops sshd" called "stop ssh.service"
refute "gate: apply doesn't start sshd" called "start ssh.service"
if grep -q 'serial console' <<<"$out"; then pass "ruleset: gate: says the way back"; else flunk "ruleset: gate: doesn't say the way back"; fi
echo 404 >"${stubs}/account-code"

# Confirming.
fresh
apply_ruleset a
setpriv --reuid=65534 --regid=65534 --clear-groups touch "${dropbox}/confirm"
check "a user may ask" test -e "${dropbox}/confirm"
confirm
check "confirm: says confirmed" state_is "$sha_a" confirmed
check "confirm: nothing pending" no_file "${state_dir}/pending"
check "confirm: records it" grep -qx "$sha_a" "${state_dir}/confirmed"
check "confirm: stops the timer" called "stop ${timer}"
check "confirm: empties the directory" no_file "${dropbox}/confirm"
: >"${stubs}/calls"
fire
refute "confirm: a late timer does nothing" called "--no-block reboot"
check "confirm: a late timer leaves the ruleset" same_file "${rules}/a" /etc/nftables.conf
reboot_vm
apply_ruleset a
check "confirm: says so at the next boot" state_is "$sha_a" confirmed
refute "confirm: no timer at the next boot" called "restart ${timer}"
check "confirm: the guard is on at the next boot" guard_on
: >"${stubs}/calls"
confirm
refute "confirm: with nothing pending, nothing" called "stop ${timer}"

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
check "broken: not installed" same_file "${rules}/c" /etc/nftables.conf
check "broken: nothing pending" no_file "${state_dir}/pending"
check "broken: sshd runs" called "start ssh.service"
apply_ruleset no-guard
check "no guard: refused" reason_is 0
check "no guard: not installed" same_file "${rules}/c" /etc/nftables.conf
reboot_vm
apply_ruleset fake-guard
check "gone after the load: exit says it is rebooting" reason_is 75
check "gone after the load: says rolled back" state_is "$sha_fake" "rolled back"
check "gone after the load: the old one back" same_file "${rules}/c" /etc/nftables.conf
check "gone after the load: rejected" test -e "${state_dir}/rejected/${sha_fake}"
check "gone after the load: reboots" called "--no-block reboot"
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
apply_ruleset a
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
apply_ruleset a
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
apply_ruleset c
check "boot, no change, no load: applied" reason_is 0
check "boot, no change, no load: the old one in the kernel" guard_on
check "boot, no change, no load: the file stays" same_file "${rules}/c" /etc/nftables.conf
check "boot, no change, no load: sshd runs" called "start ssh.service"
# ... and the old one won't load either.
cp "${rules}/broken" "${state_dir}/nftables.old"
reboot_vm
echo 200 >"${stubs}/account-code"
apply_ruleset c
check "boot, neither loads, an account: exit 1" reason_is 1
refute "boot, neither loads, an account: no guard" guard_on
refute "boot, neither loads, an account: sshd stays down" called "start ssh.service"
check "boot, neither loads, an account: sshd stopped" called "stop ssh.service"
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
as_user() { setpriv --reuid=65534 --regid=65534 --clear-groups env PATH="${stubs}:${PATH}" "$@"; }
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

# bootstrap.sh's reading of the lines: the last for that ruleset, not too old.
lines="$(printf '%s\n' \
  "[   12.3] startup-script: bastion: ruleset pending ${sha_a} at 100" \
  "bastion: settled" \
  "Nov 01 12:00:00 x systemd[1]: bastion: ruleset confirmed ${sha_a} at 200" \
  "bastion: ruleset rolled back ${sha_b} at 300" \
  "bastion: ruleset refused ${sha_c} at 400")"
read_state() { [[ "$(ruleset_state "$1" "$2" <<<"$lines")" == "$3" ]]; }
check "bootstrap reads: the last line" read_state "$sha_a" 0 confirmed
check "bootstrap reads: two words" read_state "$sha_b" 0 "rolled back"
check "bootstrap reads: refused" read_state "$sha_c" 0 refused
check "bootstrap reads: not an earlier boot's" read_state "$sha_a" 201 ""
check "bootstrap reads: another ruleset's are no news" read_state "$(printf 'd%.0s' {1..64})" 0 ""
check "bootstrap reads: nothing from nothing" test -z "$(ruleset_state "$sha_a" 0 </dev/null)"

# The units, as systemd reads them.
fresh
install -m 0755 ruleset.sh /usr/local/sbin/watchtower-ruleset
check "units: setup" tool setup
verify="$(systemd-analyze verify --man=no \
  watchtower-ruleset-rollback.timer watchtower-ruleset-rollback.service \
  watchtower-ruleset-confirm.path watchtower-ruleset-confirm.service \
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
check "units: the directory is sticky and open to all" grep -qx 'DirectoryMode=1777' /etc/systemd/system/watchtower-ruleset-confirm.path
check "units: serial output from the rollback" grep -qx 'StandardOutput=journal+console' /etc/systemd/system/watchtower-ruleset-rollback.service
check "units: serial output from the confirmation" grep -qx 'StandardOutput=journal+console' /etc/systemd/system/watchtower-ruleset-confirm.service
# The login's own part: it asks, and a shell without the directory doesn't care.
mkdir -p "$dropbox"
chmod 1777 "$dropbox"
as_user sh -c '. /etc/profile.d/watchtower-ruleset.sh'
check "units: a login asks" test -n "$(find "$dropbox" -mindepth 1 -print -quit)"
rm -rf "$dropbox"
as_user sh -c 'set -e; . /etc/profile.d/watchtower-ruleset.sh; true'
check "units: a login with no directory is unharmed" test "$?" = 0
exit "$fail"
RUN

cid="$("$rt" create --memory 3g --cap-add NET_ADMIN "$DEBIAN_IMAGE" bash /check/run.sh)"
"$rt" cp "${work}/." "${cid}:/check"
"$rt" start -a "$cid"
