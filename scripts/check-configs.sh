#!/usr/bin/env bash
# Checks every rendered host config with the program that will read it, so a
# typo fails the PR, not the deploy. Render first:
#
#   (cd ansible && ansible-playbook -i inventory/hosts.sample.yml playbooks/render.yml)
#   scripts/check-configs.sh            # docker; CONTAINER_RUNTIME=podman locally
#
# Per host in ansible/.render/:
#   quadlets      podman's quadlet generator (-dryrun), from a pinned podman image
#   watchtower.nft  nft --check, in a throwaway network namespace
#   loki          loki -verify-config
#   mimir         mimir -print.config (strict: an unknown key fails)
#   tempo         tempo -config.verify, per component
#   fluent-bit    fluent-bit --dry-run
# The Caddyfile and patroni.yml are checked where their images are built
# (scripts/build-image.sh): only our own images carry the modules and
# binaries they need.
#
# Images are the same pinned digests the hosts run (group_vars/all/images.yml).

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
render="${repo_root}/ansible/.render"
images="${repo_root}/ansible/inventory/group_vars/all/images.yml"
rt="${CONTAINER_RUNTIME:-docker}"
# quadlet from the podman release the hosts run (AlmaLinux 10: 5.8).
PODMAN_IMAGE="${PODMAN_IMAGE:-quay.io/podman/stable:v5.8.2@sha256:663e0dbf407987b7db3f20d3588c283a8228db17b282d2029a482d4d47e36964}"

[[ -d "$render" ]] || { echo "nothing rendered in ${render}; run playbooks/render.yml first" >&2; exit 1; }

image() { sed -n "s/^  $1: //p" "$images"; }
fail=0
check() { # label command...
  local label=$1 out
  shift
  if out="$("$@" 2>&1)"; then
    echo "ok    ${label}"
  else
    echo "FAIL  ${label}"
    while IFS= read -r line; do printf '      %s\n' "$line"; done <<<"$out" | tail -25
    fail=1
  fi
}
# shellcheck disable=SC2329 # called through check()
run() { "$rt" run --rm --network none "$@"; }

for host_dir in "$render"/*/; do
  host="$(basename "$host_dir")"

  check "${host}: quadlets" run -v "${host_dir}quadlets:/units:ro,Z" -e QUADLET_UNIT_DIRS=/units \
    --entrypoint /usr/libexec/podman/quadlet "$PODMAN_IMAGE" -dryrun -v

  # nft wants CAP_NET_ADMIN in a namespace of its own.
  check "${host}: nftables" unshare --user --map-root-user --net nft --check --file "${host_dir}watchtower.nft"

  check "${host}: fluent-bit" run -v "${host_dir}fluent-bit:/fluent-bit/etc:ro,Z" \
    "$(image fluentbit)" -c /fluent-bit/etc/fluent-bit.conf --dry-run

  [[ -f "${host_dir}loki/loki.yaml" ]] || continue

  check "${host}: loki" run -v "${host_dir}loki:/etc/loki:ro,Z" \
    "$(image loki)" -config.file=/etc/loki/loki.yaml -verify-config

  check "${host}: mimir" run -v "${host_dir}mimir:/etc/mimir:ro,Z" \
    "$(image mimir)" -config.file=/etc/mimir/mimir.yaml -print.config

  for cfg in "${host_dir}"tempo/*.yaml; do
    component="$(basename "$cfg" .yaml)"
    check "${host}: tempo ${component}" run -v "${cfg}:/etc/tempo/tempo.yaml:ro,Z" \
      "$(image tempo)" -target="$component" -config.file=/etc/tempo/tempo.yaml -config.verify=true
  done
done

exit "$fail"
