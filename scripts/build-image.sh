#!/usr/bin/env bash
# Build one of our images (build/<name>/), patch what Trivy finds in its OS
# packages with Copa, check it can do its job, and gate it on a Trivy scan.
#
#   scripts/build-image.sh <name> <image-ref>
#
# Shared by ci.yml (build, patch, check, scan) and scripts/publish-image.sh
# (which pushes afterwards). Needs docker, copa (.gitea/actions/setup's tool
# `copa`) and, for the images whose configs are checked, the rendered configs
# (ansible/playbooks/render.yml). Every image builds natively on the arm64
# runner, for the hosts, which are all ARM; nothing is cross-built. Each
# Dockerfile also builds on amd64, for local tests.
#
# An image on Alpine builds on the release in ALPINE_RELEASE and
# ALPINE_DIGEST, with every package upgraded as of IMAGE_DATE (the deploy
# fixes all three once), else on the newest patch release of its
# Dockerfile's minor, today (scripts/image-tag.sh --inputs). A new
# IMAGE_DATE misses the build cache at the Dockerfile's `apk upgrade`.
#
# After the build, in order:
#   1. Trivy lists the fixable HIGH/CRITICAL findings in the image's OS
#      packages (Alpine's or Debian's), as JSON.
#   2. If there are any, Copa (project-copacetic) upgrades just those
#      packages, with the image's own package manager, in one new layer, and
#      the patched image becomes <image-ref>. Nothing else in the image moves.
#      PostgreSQL's own packages are never Copa's: Patroni's image has them
#      from apt.postgresql.org (every version says "pgdg"), and moving
#      PostgreSQL is a decision, not a patch. A hole in one is left in, so
#      the gate fails on it and it waits for a person.
#   3. The checks below run on that image, the one that ships.
#   4. Trivy gates it: the build fails on any fixable HIGH/CRITICAL finding
#      still there in what we control, the image's OS packages and everything
#      we compile. Copa patches no libraries, so a finding in what we compile
#      still fails here. In an image that wraps an upstream release binary,
#      findings in the libraries inside that binary are printed but don't
#      fail the build: we can't patch someone else's binary, and its next
#      release fixes them.
#
# Copa only runs when this builds a new tag. The deploy reuses a tag that's
# in the registry (scripts/publish-image.sh), but every tag has the day in it
# (scripts/image-tag.sh), so each day's first deploy rebuilds and patches
# every image.
#
# Checks, per image:
#   caddy    `caddy validate` on the proxy's rendered Caddyfile, run the way
#            the quadlet runs it (UID 1000, read-only root, writable /data,
#            /config and /tmp, no capabilities but binding 443), so an unknown
#            directive, a missing plugin or a module that can't provision
#            there (Coraza without a writable /tmp) fails here, not on the
#            proxy. Then the adapted config holds agent peers to writing
#            telemetry (scripts/check-agent-gating.sh).
#   patroni  `patroni --validate-config` on a node's rendered patroni.yml
#            (etcd being unreachable from the build is the one complaint
#            ignored).
#   wg-easy  iptables is the nftables backend (legacy needs kernel modules
#            an nftables host doesn't load), wg-quick's tools are there, and
#            libsql's native binding loads.
#
# Configs go in over stdin, and Trivy gets the image over stdin (`docker
# save | docker run -i`), instead of bind mounts or the docker socket: on the
# Gitea runners the daemon is Docker-in-Docker, where a host path resolves on
# the daemon's side. Trivy's database stays in a volume of that daemon's
# (watchtower-trivy-cache), so both scans share one download. Copa uses the
# same daemon's BuildKit ($DOCKER_HOST), which can read the image just built
# because that daemon keeps images in containerd's image store: Docker 29's
# default on a new data root, which every arm64 job's daemon has. A daemon on
# the older storage driver can't, and Copa fails there.
#
# For a Debian image, Copa runs apt in a helper image of its own,
# ghcr.io/project-copacetic/copacetic/debian:stable-slim, and what that
# fetches goes into ours. scripts/copa-source-policy.json (a BuildKit source
# policy, which Copa passes on) pins that helper by digest and refuses any
# other image of Copa's, so a new Copa or Debian that wants a different one
# fails the build instead of pulling it unpinned. Alpine images need no
# helper. Bump the digest the way the other pins are bumped: check what
# `skopeo inspect --raw docker://...:stable-slim | sha256sum` gives.

set -euo pipefail

TRIVY_IMAGE="docker.io/aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
TRIVY_CACHE=watchtower-trivy-cache

usage() { echo "usage: $0 <name> <image-ref>" >&2; exit 1; }
[[ $# -eq 2 ]] || usage
what="$1" ref="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
render="${repo_root}/ansible/.render"
[[ -f "${repo_root}/build/${what}/Dockerfile" ]] || usage
[[ "$ref" == *:* ]] || { echo "the image reference needs a tag: ${ref}" >&2; exit 1; }

# What Trivy blocks on: everything (images we compile), or the OS packages
# only (images around an upstream release binary).
gate=all

needs() { [[ -f "$1" ]] || { echo "no ${1}; run ansible/playbooks/render.yml first" >&2; exit 1; }; }

case "$what" in
  caddy) needs "${render}/watchtower-proxy/caddy/Caddyfile" ;;
  patroni) needs "${render}/watchtower-1/patroni/patroni.yml" ;;
esac

build_args=()
if grep -q '^ARG ALPINE=' "${repo_root}/build/${what}/Dockerfile"; then
  if [[ -z "${ALPINE_RELEASE:-}" || -z "${ALPINE_DIGEST:-}" || -z "${IMAGE_DATE:-}" ]]; then
    inputs="$("${repo_root}/scripts/image-tag.sh" --inputs)"
    while read -r kv; do export "${kv?}"; done <<<"$inputs"
  fi
  echo "==> Building on Alpine ${ALPINE_RELEASE} (${ALPINE_DIGEST}), packages as of ${IMAGE_DATE}"
  build_args+=(--build-arg "ALPINE=docker.io/library/alpine:${ALPINE_RELEASE}@${ALPINE_DIGEST}"
    --build-arg "IMAGE_DATE=${IMAGE_DATE}")
fi

DOCKER_BUILDKIT=1 docker build "${build_args[@]}" -t "$ref" "${repo_root}/build/${what}"

# 1. What Trivy finds to fix in the OS packages, and of that, what Copa gets.
scan="$(mktemp)" report="$(mktemp)"
patched="${ref%:*}:${ref##*:}-patched"
trap 'rm -f "$scan" "$report"; docker image rm "$patched" >/dev/null 2>&1 || true' EXIT

echo "==> Listing ${ref}'s fixable HIGH/CRITICAL findings in its OS packages"
docker save "$ref" | docker run --rm -i -v "${TRIVY_CACHE}:/root/.cache/trivy" --entrypoint sh "$TRIVY_IMAGE" -c '
  set -e
  cat >/tmp/image.tar
  exec trivy image --input /tmp/image.tar --pkg-types os --severity HIGH,CRITICAL --ignore-unfixed \
    --no-progress --format json
' >"$scan"

# PostgreSQL's own packages: from apt.postgresql.org (a "pgdg" version), or
# named as its packages are.
postgres='def postgres: (.InstalledVersion // "" | test("pgdg")) or (.PkgName | test("^(postgresql|libpq|libecpg|libpgtypes)"));'
jq "${postgres}"' .Results[]? |= (.Vulnerabilities |= (if . == null then . else map(select(postgres | not)) end))' \
  "$scan" >"$report"
held="$(jq -r "${postgres}"' [.Results[]?.Vulnerabilities[]? | select(postgres) | "  \(.PkgName) \(.InstalledVersion) -> \(.FixedVersion) (\(.VulnerabilityID), \(.Severity))"] | unique | .[]' "$scan")"
if [[ -n "$held" ]]; then
  echo "==> Left for a person, PostgreSQL's own (the gate below fails on them):"
  echo "$held"
fi
fixable="$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$report")"

# 2. Copa upgrades those packages, and the patched image takes the tag.
if ((fixable > 0)); then
  echo "==> ${fixable} to fix:"
  jq -r '[.Results[]?.Vulnerabilities[]? | "  \(.PkgName) \(.InstalledVersion) -> \(.FixedVersion) (\(.VulnerabilityID), \(.Severity))"] | unique | .[]' "$report"
  echo "==> Patching them: $(copa --version), on $(docker info --format 'Docker {{.ServerVersion}}, storage {{.Driver}}')"
  EXPERIMENTAL_BUILDKIT_SOURCE_POLICY="${repo_root}/scripts/copa-source-policy.json" \
    copa patch --image "$ref" --report "$report" --tag "${ref##*:}-patched" \
    --addr "docker://${DOCKER_HOST:-unix:///var/run/docker.sock}" --timeout 20m --progress plain
  docker image inspect "$patched" >/dev/null 2>&1 || { echo "copa finished but there is no ${patched}" >&2; exit 1; }
  docker tag "$patched" "$ref"
  docker image rm "$patched" >/dev/null
else
  echo "==> Nothing to patch"
fi

# 3. The checks, on the image that ships.
case "$what" in
  caddy)
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
      <"${render}/watchtower-proxy/caddy/Caddyfile"
    echo "==> Agent peers may only write telemetry (scripts/check-agent-gating.sh)"
    docker run --rm -i --network none -e DOMAIN=watchtower.jasonmross.dev -e GCP_PROJECT=watchtower-observe \
      --entrypoint sh "$ref" -c 'cat >/tmp/Caddyfile && exec caddy adapt --config /tmp/Caddyfile --adapter caddyfile' \
      <"${render}/watchtower-proxy/caddy/Caddyfile" | "${repo_root}/scripts/check-agent-gating.sh" caddy
    ;;
  patroni)
    echo "==> Validating a node's patroni.yml with ${ref}"
    # The passwords come from the environment at run time, as they will on
    # the nodes. The validator also tries to reach every etcd member, which
    # no build can; only those complaints are ignored, any other fails.
    out="$(docker run --rm -i --network none \
      -e PATRONI_RESTAPI_PASSWORD=x -e PATRONI_SUPERUSER_PASSWORD=x -e PATRONI_REPLICATION_PASSWORD=x \
      -e PATRONI_REWIND_PASSWORD=x \
      --entrypoint sh "$ref" -c 'cat >/tmp/patroni.yml && exec patroni --validate-config /tmp/patroni.yml' \
      <"${render}/watchtower-1/patroni/patroni.yml" 2>&1)" || true
    problems="$(grep -v ' is not reachable$' <<<"$out" || true)"
    if [[ -n "$problems" ]]; then
      echo "patroni.yml failed validation:" >&2
      echo "$problems" >&2
      exit 1
    fi
    ;;
  wg-easy)
    echo "==> Checking ${ref} has what wg-easy and wg-quick need"
    docker run --rm --network none --entrypoint sh "$ref" -c '
      set -e
      iptables -V | grep -q "(nf_tables)" || { iptables -V; echo "iptables is not the nftables backend" >&2; exit 1; }
      for c in wg wg-quick bash ip node dumb-init cli; do command -v "$c" >/dev/null || { echo "missing $c" >&2; exit 1; }; done
      test -f /app/server/index.mjs
      cd /app/server && node -e "require(\"libsql\")"
      echo "ok: $(iptables -V), $(wg --version | cut -d" " -f1-2), node $(node --version)"'
    ;;
  *)
    echo "build-image.sh has no checks for ${what}; add them before shipping it" >&2
    exit 1
    ;;
esac

# 4. The gate, on what's left after the patch.
echo "==> Scanning ${ref} with ${TRIVY_IMAGE} (blocking: ${gate})"
docker save "$ref" | docker run --rm -i -v "${TRIVY_CACHE}:/root/.cache/trivy" -e GATE="$gate" --entrypoint sh "$TRIVY_IMAGE" -c '
  set -e
  cat >/tmp/image.tar
  scan() { trivy image --input /tmp/image.tar --severity HIGH,CRITICAL --ignore-unfixed --no-progress "$@"; }
  if [ "$GATE" = all ]; then
    scan --exit-code 1
  else
    scan --pkg-types os --exit-code 1
    echo "==> Findings inside the upstream binary (reported, not blocking):"
    scan --pkg-types library --exit-code 0
  fi
'
