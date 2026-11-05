#!/usr/bin/env bash
# The bastion's Alloy config (config/alloy/bastion.alloy) must put no user or
# login in a label, and check-alloy-scrub.sh only tests log lines. This tests
# the other two places a uid gets in, with Alloy itself where it can:
#
#   units   the journal's relabel rules, on made-up units: each login's
#           user@<uid>.service and session-<id>.scope collapse to one value.
#   mounts  the exporter's filesystem exclusions: /run/user/<uid>, mounted for
#           each login, gets no series. Matched with grep, as a CI pod has no
#           such mount.
#
#   scripts/check-bastion-labels.sh
#
# Needs alloy and jq.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config="${repo_root}/config/alloy/bastion.alloy"
port="${ALLOY_TEST_PORT:-12399}"

work="$(mktemp -d)"
pid=
cleanup() { [[ -n "$pid" ]] && kill "$pid" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT

bad=0
flunk() { echo "FAIL  $*"; bad=1; }

# --- units --------------------------------------------------------------------
# __journal__systemd_unit|__journal__systemd_user_unit|the unit label wanted
units=(
  'user@3141592653.service||user@.service'
  'user-runtime-dir@3141592653.service||user-runtime-dir@.service'
  'session-7.scope||session.scope'
  'session-c3.scope||session.scope'
  'user@3141592653.service|session-7.scope|session.scope'
  'sshd.service||sshd.service'
  'user@3141592653.service|dbus.service|dbus.service'
)
{
  printf 'discovery.relabel "units" {\n\ttargets = [\n'
  for i in "${!units[@]}"; do
    IFS='|' read -r unit user_unit _ <<<"${units[$i]}"
    printf '\t\t{"__address__" = "%s", "__journal__systemd_unit" = "%s", "__journal__systemd_user_unit" = "%s"},\n' "$i" "$unit" "$user_unit"
  done
  printf '\t]\n'
  # The journal's rules as they are, without the block's own lines.
  sed -n '/^loki\.relabel "journal" {$/,/^}$/p' "$config" | sed '1d;$d' | grep -v 'forward_to'
  printf '}\n'
} >"${work}/units.alloy"

alloy run --server.http.listen-addr="127.0.0.1:${port}" --storage.path="${work}/data" \
  --disable-reporting "${work}/units.alloy" >"${work}/alloy.log" 2>&1 &
pid=$!
api="http://127.0.0.1:${port}/api/v0/web/components/discovery.relabel.units"
for _ in $(seq 60); do
  curl -fsS -o "${work}/out.json" "$api" 2>/dev/null && [[ "$(jq '.exports | length' "${work}/out.json")" -gt 0 ]] && break
  kill -0 "$pid" 2>/dev/null || { tail -20 "${work}/alloy.log" >&2; exit 1; }
  sleep 0.5
done
for i in "${!units[@]}"; do
  IFS='|' read -r unit user_unit want <<<"${units[$i]}"
  got="$(jq -r --arg i "$i" '.exports[] | select(.name == "output") | .value.value[].value
    | map({(.key): .value.value}) | add | select(.__address__ == $i) | .unit // ""' "${work}/out.json")"
  if [[ "$got" == "$want" ]]; then
    echo "ok    unit ${unit}${user_unit:+ (${user_unit})} -> ${got}"
  else
    flunk "unit ${unit}${user_unit:+ (${user_unit})} -> ${got:-nothing}, want ${want}"
  fi
done

# --- mounts -------------------------------------------------------------------
exclude="$(sed -n 's/^[[:space:]]*mount_points_exclude = "\(.*\)"$/\1/p' "$config")"
[[ -n "$exclude" ]] || flunk "no mount_points_exclude in ${config}"
for mount in /run/user/3141592653 /run/user/3141592653/doc /run/user/0 /proc /sys/fs/cgroup; do
  if grep -Eq -- "$exclude" <<<"$mount"; then echo "ok    mount ${mount}: no series"; else flunk "mount ${mount} ships a series"; fi
done
for mount in / /boot/efi /var; do
  if grep -Eq -- "$exclude" <<<"$mount"; then flunk "mount ${mount} has no series"; else echo "ok    mount ${mount}: ships"; fi
done

[[ "$bad" -eq 0 ]] || { echo "the bastion's config puts a user or a login in a label (above)" >&2; exit 1; }
