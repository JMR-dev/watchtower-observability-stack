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
#   guard  nftables.conf checked, loaded twice (a reload, as at boot), and
#          probed on 169.254.169.254 (on lo): root reaches it over HTTP,
#          other uids are refused at once, and every uid still reaches its
#          DNS (53) and NTP (123), and everything else. The same on its IPv6
#          address, fd20:ce::254, where the container has IPv6.
#
#   scripts/check-bastion.sh            # docker; CONTAINER_RUNTIME=podman locally
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

cp "${repo_root}/config/bastion/startup.sh" "${repo_root}/config/bastion/nftables.conf" "$work/"
# The line bootstrap.sh stops the VM on, which run.sh checks main prints.
grep -qF "grep -cF 'bastion: settled'" "${repo_root}/scripts/bootstrap.sh" || {
  echo "FAIL  bootstrap.sh doesn't wait for 'bastion: settled'"
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
UDP = [(META, 53), (META, 123), (META, 9999)]
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
apt-get install -y -qq --no-install-recommends nftables python3 iproute2 >/dev/null

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
  updates() { :; }
  guard() { echo guard; }
  installed() { return 1; }
  apt_install() { echo apt; }
  fetch_peer() { have_peer=""; }
  teardown() { echo teardown; }
  main 2>/dev/null | tr '\n' ' '
)"
if [[ "$main_order" == "guard bastion: metadata guard loaded apt bastion: settled teardown " ]]; then
  pass "apt: main says settled only after the guard and apt"
else
  flunk "apt: main's order is: ${main_order}"
fi
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
probe 65534 "$meta" udp 123 open
probe 65534 127.0.0.1 tcp 8081 open
if [[ -n "$v6" ]]; then
  probe 0 fd20:ce::254 tcp 80 open
  probe 65534 fd20:ce::254 tcp 80 refused
  probe 65534 fd20:ce::254 udp 53 open
else
  echo "skip  guard: no IPv6 here, so fd20:ce::254 is only nft --check'ed"
fi
if nft list chain inet metadata_guard metadata | grep -Eq 'counter packets [1-9]'; then
  pass "guard: refusals counted"
else
  flunk "guard: no refusal counted"
fi
exit "$fail"
RUN

cid="$("$rt" create --cap-add NET_ADMIN "$DEBIAN_IMAGE" bash /check/run.sh)"
"$rt" cp "${work}/." "${cid}:/check"
"$rt" start -a "$cid"
