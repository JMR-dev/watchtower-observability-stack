#!/usr/bin/env bash
# Tests the break-glass bastion's startup pieces (config/bastion/) in Debian
# 13, the bastion's own release, since the only other place they run is the
# VM itself:
#
#   peer   startup.sh's check_peer on made-up configs (dummy keys): it takes
#          wg-easy's agent config as it is, adds a missing MTU and keepalive,
#          drops DNS, and refuses hooks, Table, FwMark, SaveConfig, more
#          routes, a second peer or none, without echoing the config.
#   guard  nftables.conf checked, loaded twice (a reload, as at boot), and
#          probed on 169.254.169.254 (on lo): root reaches it over HTTP,
#          other uids are refused at once, and every uid still reaches its
#          DNS (53) and NTP (123), and everything else.
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

cat >"${work}/probe.py" <<'PY'
"""serve: answers "ok" on the guard's ports. <addr> <tcp|udp> <port>: prints
open, refused or timeout."""
import socket
import sys
import threading
import time

META = "169.254.169.254"
TCP = [(META, 80), (META, 443), (META, 8080), (META, 53), ("127.0.0.1", 8081)]
UDP = [(META, 53), (META, 123), (META, 9999)]


def tcp(addr):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(addr)
    s.listen()
    while True:
        c, _ = s.accept()
        c.sendall(b"ok")
        c.close()


def udp(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(addr)
    while True:
        _, peer = s.recvfrom(64)
        s.sendto(b"ok", peer)


if sys.argv[1] == "serve":
    for a in TCP:
        threading.Thread(target=tcp, args=(a,), daemon=True).start()
    for a in UDP:
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
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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

# What wg-easy publishes for an agent (roles/edge/tasks/peer.yml pins it):
# taken as it is.
cat >peers/wg-easy.want <<'EOF'
[Interface]
PrivateKey = dummy-private-key
Address = 10.8.0.129/32
MTU = 1380
[Peer]
PublicKey = dummy-public-key
PresharedKey = dummy-preshared-key
AllowedIPs = 10.8.0.0/24
PersistentKeepalive = 25
Endpoint = vpn.watchtower.jasonmross.dev:51820
EOF
peer_case wg-easy accept <<'EOF'
[Interface]
PrivateKey = dummy-private-key
Address = 10.8.0.129/32
MTU = 1380

[Peer]
PublicKey = dummy-public-key
PresharedKey = dummy-preshared-key
AllowedIPs = 10.8.0.0/24
PersistentKeepalive = 25
Endpoint = vpn.watchtower.jasonmross.dev:51820
EOF

# No MTU or keepalive, a DNS line, comments, CRLF and odd case and spacing:
# normalised.
cat >peers/normalised.want <<'EOF'
[interface]
MTU = 1380
privatekey=dummy-private-key
Address = 10.8.0.129/32
[PEER]
PersistentKeepalive = 25
PublicKey = dummy-public-key
allowedips = 10.8.0.0/24
Endpoint = 192.0.2.1:51820
EOF
peer_case normalised accept <<'EOF'
# made by wg-easy
[interface]
privatekey=dummy-private-key
  Address = 10.8.0.129/32   # the agent half
dns = 1.1.1.1
[PEER]
PublicKey = dummy-public-key
allowedips = 10.8.0.0/24
Endpoint = 192.0.2.1:51820
EOF
sed 's/$/\r/' peers/normalised.in >peers/crlf.in
if check_peer peers/crlf.in peers/crlf.out 2>/dev/null && diff -q peers/normalised.want peers/crlf.out >/dev/null; then
  pass "peer crlf: accepted"
else
  flunk "peer crlf: not normalised"
fi

good_interface='[Interface]
PrivateKey = dummy-private-key
Address = 10.8.0.129/32'
good_peer='[Peer]
PublicKey = dummy-public-key
AllowedIPs = 10.8.0.0/24
Endpoint = 192.0.2.1:51820'
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
set -e

# --- guard: nftables.conf ----------------------------------------------------
ip addr add 169.254.169.254/32 dev lo
nft --check --file nftables.conf
pass "guard: nft --check"
nft --file nftables.conf
nft --file nftables.conf
if [[ "$(nft list tables | grep -c 'metadata_guard')" == 1 ]]; then
  pass "guard: loads, and reloads in place"
else
  flunk "guard: not exactly one metadata_guard table after a reload"
fi
python3 probe.py serve &
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
