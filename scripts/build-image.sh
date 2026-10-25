#!/usr/bin/env bash
# Build one of our two images, check it can read the config it will run with,
# and gate it on a Trivy scan.
#
#   scripts/build-image.sh caddy   <image-ref>    # on `docker-arm64`
#   scripts/build-image.sh patroni <image-ref>    # on `docker-arm64`
#
# Shared by ci.yml (build + check + scan) and deploy.yml (which pushes the
# ref afterwards). Needs docker and the rendered configs
# (ansible/playbooks/render.yml). Both build natively on the arm64 runner,
# for the hosts, which are all ARM; nothing is cross-built. Fails on any fixable
# HIGH/CRITICAL finding.
#
#   caddy    `caddy validate` on the proxy's rendered Caddyfile, run the way
#            the quadlet runs it (UID 1000, read-only root, writable /data,
#            /config and /tmp, no capabilities but binding 443), so an unknown
#            directive, a missing plugin or a module that can't provision
#            there (Coraza without a writable /tmp) fails here, not on the
#            proxy.
#   patroni  `patroni --validate-config` on a node's rendered patroni.yml
#            (etcd being unreachable from the build is the one complaint
#            ignored).
#
# Configs go in over stdin, and Trivy gets the image over stdin (`docker
# save | docker run -i`), instead of bind mounts or the docker socket: on the
# Gitea runners the daemon is Docker-in-Docker, where a host path resolves on
# the daemon's side.

set -euo pipefail

TRIVY_IMAGE="docker.io/aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"

usage() { echo "usage: $0 caddy|patroni <image-ref>" >&2; exit 1; }
[[ $# -eq 2 ]] || usage
what="$1" ref="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
render="${repo_root}/ansible/.render"

case "$what" in
  caddy)
    caddyfile="${render}/watchtower-proxy/caddy/Caddyfile"
    [[ -f "$caddyfile" ]] || { echo "no ${caddyfile}; run ansible/playbooks/render.yml first" >&2; exit 1; }
    DOCKER_BUILDKIT=1 docker build -t "$ref" "${repo_root}/build/caddy"
    echo "==> Validating the proxy's Caddyfile with ${ref} as the proxy runs it"
    # Provisioning needs neither the network nor the DNS-01 key; the bind
    # address need not exist for validation.
    docker run --rm -i --network none --read-only --user 1000:1000 \
      --cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges \
      --tmpfs /data --tmpfs /config --tmpfs /tmp \
      -e DOMAIN=watchtower.jasonmross.dev -e GCP_PROJECT=watchtower-observe \
      -e XDG_CONFIG_HOME=/config -e XDG_DATA_HOME=/data \
      -e GOOGLE_APPLICATION_CREDENTIALS=/etc/caddy-dns/key.json \
      --entrypoint sh "$ref" -c 'cat >/tmp/Caddyfile && exec caddy validate --config /tmp/Caddyfile --adapter caddyfile' \
      <"$caddyfile"
    ;;
  patroni)
    config="${render}/watchtower-1/patroni/patroni.yml"
    [[ -f "$config" ]] || { echo "no ${config}; run ansible/playbooks/render.yml first" >&2; exit 1; }
    DOCKER_BUILDKIT=1 docker build -t "$ref" "${repo_root}/build/patroni"
    echo "==> Validating a node's patroni.yml with ${ref}"
    # The passwords come from the environment at run time, as they will on
    # the nodes. The validator also tries to reach every etcd member, which
    # no build can; only those complaints are ignored, any other fails.
    out="$(docker run --rm -i --network none \
      -e PATRONI_RESTAPI_PASSWORD=x -e PATRONI_SUPERUSER_PASSWORD=x -e PATRONI_REPLICATION_PASSWORD=x \
      --entrypoint sh "$ref" -c 'cat >/tmp/patroni.yml && exec patroni --validate-config /tmp/patroni.yml' \
      <"$config" 2>&1)" || true
    problems="$(grep -v ' is not reachable$' <<<"$out" || true)"
    if [[ -n "$problems" ]]; then
      echo "patroni.yml failed validation:" >&2
      echo "$problems" >&2
      exit 1
    fi
    ;;
  *) usage ;;
esac

echo "==> Scanning ${ref} with ${TRIVY_IMAGE}"
docker save "$ref" | docker run --rm -i --entrypoint sh "$TRIVY_IMAGE" -c '
  set -e
  cat >/tmp/image.tar
  trivy image --input /tmp/image.tar \
    --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress
'
