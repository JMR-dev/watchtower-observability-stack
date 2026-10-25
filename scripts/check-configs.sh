#!/usr/bin/env bash
# Checks every rendered host config with the program that will read it, so a
# typo fails the PR, not the deploy. Render first:
#
#   (cd ansible && ansible-playbook -i inventory/hosts.sample.yml playbooks/render.yml)
#   scripts/check-configs.sh            # docker; CONTAINER_RUNTIME=podman locally
#
# Per host in ansible/.render/:
#   quadlets      podman's quadlet generator (-dryrun), from a pinned podman image
#   loki          loki -verify-config
#   mimir         mimir -print.config (strict: an unknown key fails)
#   tempo         tempo -config.verify, per component
#   fluent-bit    fluent-bit --dry-run
#   scripts       shellcheck on the host scripts (reboot, Postgres backup)
# The firewall is checked by the ansible job (it needs a network namespace,
# not a container); the Caddyfile and patroni.yml where their images are
# built (scripts/build-image.sh): only our own images carry the modules and
# binaries they need.
#
# Images are the same pinned digests the hosts run (group_vars/all/images.yml).
# Files go into each container with `cp`, not a bind mount: on the Gitea
# runners the daemon is Docker-in-Docker and can't see this filesystem.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
render="${repo_root}/ansible/.render"
images="${repo_root}/ansible/inventory/group_vars/all/images.yml"
rt="${CONTAINER_RUNTIME:-docker}"
# quadlet from the podman release the hosts run (AlmaLinux 10: 5.8).
PODMAN_IMAGE="${PODMAN_IMAGE:-quay.io/podman/stable:v5.8.2@sha256:663e0dbf407987b7db3f20d3588c283a8228db17b282d2029a482d4d47e36964}"
# The shellcheck release the shell job runs (.gitea/actions/setup).
SHELLCHECK_IMAGE="${SHELLCHECK_IMAGE:-docker.io/koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d}"

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
# with <src> <dest> <image> [args...]: create a container, copy src (a file,
# or a directory's contents) to dest, run it to completion, remove it.
# shellcheck disable=SC2329 # called through check()
with() {
  local src=$1 dest=$2 image=$3 cid rc=0
  shift 3
  cid="$("$rt" create --network none "$image" "$@")"
  if [[ -d "$src" ]]; then
    "$rt" cp "${src}/." "${cid}:${dest}"
  else
    "$rt" cp "$src" "${cid}:${dest}"
  fi
  "$rt" start --attach "$cid" || rc=$?
  "$rt" rm -f "$cid" >/dev/null
  return "$rc"
}

for host_dir in "$render"/*/; do
  host="$(basename "$host_dir")"

  check "${host}: quadlets" with "${host_dir}quadlets" /etc/containers/systemd "$PODMAN_IMAGE" \
    /usr/libexec/podman/quadlet -dryrun -v

  check "${host}: fluent-bit" with "${host_dir}fluent-bit" /fluent-bit/etc "$(image fluentbit)" \
    -c /fluent-bit/etc/fluent-bit.conf --dry-run

  for script in "${host_dir}"*.sh; do
    check "${host}: $(basename "$script")" with "$script" /mnt/script.sh "$SHELLCHECK_IMAGE" /mnt/script.sh
  done

  [[ -f "${host_dir}loki/loki.yaml" ]] || continue

  check "${host}: loki" with "${host_dir}loki/loki.yaml" /etc/loki/loki.yaml "$(image loki)" \
    -config.file=/etc/loki/loki.yaml -verify-config

  check "${host}: mimir" with "${host_dir}mimir" /etc/mimir "$(image mimir)" \
    -config.file=/etc/mimir/mimir.yaml -print.config

  for cfg in "${host_dir}"tempo/*.yaml; do
    component="$(basename "$cfg" .yaml)"
    check "${host}: tempo ${component}" with "$cfg" /tempo.yaml "$(image tempo)" \
      -target="$component" -config.file=/tempo.yaml -config.verify=true
  done
done

exit "$fail"
