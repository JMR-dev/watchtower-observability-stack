#!/usr/bin/env bash
# Reach the proxy over the VPN without a kernel interface: wireproxy, a
# userspace WireGuard peer, forwards a local port to SSH on the tunnel
# address. The deploy's way in (deploy.yml, wireguard-deploy-peer). It also
# works from any machine that holds a wg-easy client config and has no VPN up.
#
#   scripts/vpn-tunnel.sh start <peer.conf> [127.0.0.1:2222]
#       starts wireproxy in the background with that wg-easy client config,
#       waits until SSH answers through the forward (up to a minute), and
#       prints the line for scripts/ssh-config.sh:
#           WATCHTOWER_VPN_FORWARD=127.0.0.1:2222
#   scripts/vpn-tunnel.sh stop
#
# The peer config holds a private key. It's copied into a 0600 file under
# $RUNNER_TEMP (else $XDG_RUNTIME_DIR), never printed, and shredded on stop.
# No root, no NET_ADMIN: the GKE job pods are unprivileged. Needs wireproxy
# (the setup action's `wireproxy` tool) and, for the tunnel address, the
# inventory (ansible/inventory/hosts.yml; else 10.8.0.1).

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="${RUNNER_TEMP:-${XDG_RUNTIME_DIR:-/tmp}}/watchtower-wireproxy"
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

stop() {
  if [[ -s "${dir}/pid" ]]; then
    kill "$(cat "${dir}/pid")" 2>/dev/null || true
  fi
  if [[ -d "$dir" ]]; then
    find "$dir" -type f -exec shred -u {} + 2>/dev/null || true
    rm -rf "$dir"
  fi
}

banner() { # host port: the first bytes the far end sends, if any within 5 s
  # The inner shell expands its own arguments.
  # shellcheck disable=SC2016
  timeout 5 bash -c 'exec 3<>"/dev/tcp/$1/$2" && head -c 4 <&3' _ "$1" "$2" 2>/dev/null || true
}

start() {
  local peer=$1 bind=${2:-127.0.0.1:2222} tunnel=10.8.0.1 conf
  [[ -r "$peer" ]] || die "can't read ${peer}"
  command -v wireproxy >/dev/null || die "wireproxy is not installed"
  if [[ -s "${repo_root}/ansible/inventory/hosts.yml" ]]; then
    tunnel="$(jq -r '.all.vars.watchtower_tunnel_ip' "${repo_root}/ansible/inventory/hosts.yml")"
  fi
  stop
  (umask 077 && mkdir -p "$dir")
  conf="${dir}/wireproxy.conf"
  # The client config as wg-easy wrote it, then one forward to the proxy's SSH.
  (umask 077 && { cat "$peer"; printf '\n[TCPClientTunnel]\nBindAddress = %s\nTarget = %s:22\n' "$bind" "$tunnel"; } >"$conf")
  wireproxy --silent --config "$conf" >"${dir}/log" 2>&1 &
  echo $! >"${dir}/pid"
  # The forward listens at once; it answers with sshd's banner only once
  # the tunnel is up.
  local i
  for ((i = 0; i < 12; i++)); do
    if [[ "$(banner "${bind%:*}" "${bind##*:}")" == SSH- ]]; then
      printf 'WATCHTOWER_VPN_FORWARD=%s\n' "$bind"
      return 0
    fi
    kill -0 "$(cat "${dir}/pid")" 2>/dev/null || break
    sleep 5
  done
  echo "the tunnel to ${tunnel}:22 never came up; wireproxy said:" >&2
  tail -20 "${dir}/log" >&2 || true
  stop
  exit 1
}

case "${1:-}" in
  start) [[ $# -ge 2 ]] || die "usage: $0 start <peer.conf> [bind]"; start "$2" "${3:-}" ;;
  stop) stop ;;
  *) die "usage: $0 start <peer.conf> [127.0.0.1:2222] | stop" ;;
esac
