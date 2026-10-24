#!/usr/bin/env bash
# Build one of the two images and gate it on a Trivy scan.
#
#   scripts/build-image.sh caddy <image-ref>
#   scripts/build-image.sh fipd  <image-ref> [version]
#
# Shared by ci.yml (build + scan only) and deploy.yml (which pushes the ref
# afterwards). Needs docker. Fails on any fixable HIGH/CRITICAL finding. For
# Caddy it also runs `caddy validate` on the edge Caddyfile with the image it
# just built, under the edge pod's security context, so a Caddyfile the
# binary can't parse (an unknown directive, a missing plugin) or a module that
# can't provision there (Coraza without a writable /tmp) fails here and not on
# the edge pod.
#
# Trivy gets the image over stdin (`docker save | docker run -i`) instead of a
# bind-mounted docker socket: on the Gitea runners the daemon is rootless
# Docker-in-Docker, where a socket path would resolve on the daemon's side.

set -euo pipefail

TRIVY_IMAGE="docker.io/aquasec/trivy:0.76.1"

[[ $# -ge 2 ]] || { echo "usage: $0 caddy|fipd <image-ref> [version]" >&2; exit 1; }
what="$1" ref="$2" version="${3:-dev}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$what" in
  caddy)
    DOCKER_BUILDKIT=1 docker build -t "$ref" "${repo_root}/build/caddy"
    echo "==> Validating the edge Caddyfile with ${ref} as the edge pod runs it"
    # The caddy container's settings in infra/apps/edge.go: UID 1000, no
    # capabilities, a read-only root, and writable only at /data, /config and
    # /tmp (TestEdge holds edge.go to exactly those three). The Caddyfile
    # goes in over stdin, not a bind mount (the daemon may not see this
    # filesystem), and lands in /tmp: it imports nothing, so where it sits
    # doesn't matter. Provisioning needs neither the network nor the DNS-01
    # key.
    docker run --rm -i --network none --read-only --user 1000:1000 \
      --cap-drop ALL --security-opt no-new-privileges \
      --tmpfs /data --tmpfs /config --tmpfs /tmp \
      -e DOMAIN=watchtower.jasonmross.dev -e GCP_PROJECT=watchtower-observe \
      -e XDG_CONFIG_HOME=/config -e GOOGLE_APPLICATION_CREDENTIALS=/etc/caddy-dns/key.json \
      --entrypoint sh "$ref" -c 'cat >/tmp/Caddyfile && exec caddy validate --config /tmp/Caddyfile --adapter caddyfile' \
      <"${repo_root}/infra/apps/files/Caddyfile"
    ;;
  fipd)
    DOCKER_BUILDKIT=1 docker build --build-arg VERSION="$version" -t "$ref" "${repo_root}/fipd"
    ;;
  *)
    echo "usage: $0 caddy|fipd <image-ref> [version]" >&2
    exit 1
    ;;
esac

echo "==> Scanning ${ref} with ${TRIVY_IMAGE}"
docker save "$ref" | docker run --rm -i --entrypoint sh "$TRIVY_IMAGE" -c '
  set -e
  cat >/tmp/image.tar
  trivy image --input /tmp/image.tar \
    --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress
'
