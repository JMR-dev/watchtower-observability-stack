#!/usr/bin/env bash
# Build, check, scan and push one of our images to Artifact Registry, or
# reuse this commit's if it is already there. Prints `<image>@sha256:...`
# last: the digest the hosts will run, never a movable tag.
#
#   GAR_PUSH_KEY=<json> scripts/publish-image.sh caddy|patroni <tag>
#
# deploy.yml runs it on the arm64 runner, for both. Tags are immutable in
# the repo (scripts/bootstrap.sh), so a tag that exists is this commit's
# build, already checked and scanned. The key can write only to that one
# repo.

set -euo pipefail

REGISTRY="${REGISTRY:-europe-west3-docker.pkg.dev}"
REPO="${REPO:-${REGISTRY}/watchtower-observe/watchtower}"

[[ $# -eq 2 ]] || { echo "usage: $0 caddy|patroni <tag>" >&2; exit 1; }
what="$1" tag="$2"
[[ -n "${GAR_PUSH_KEY:-}" ]] || { echo "GAR_PUSH_KEY is not set" >&2; exit 1; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ref="${REPO}/${what}:${tag}"

# The key goes in on stdin; docker keeps it in its config until the job's
# cleanup step removes it.
printf '%s' "$GAR_PUSH_KEY" | docker login -u _json_key --password-stdin "https://${REGISTRY}" >/dev/null

if docker pull -q "$ref" >/dev/null 2>&1; then
  echo "${ref} already built, checked and scanned" >&2
else
  "${repo_root}/scripts/build-image.sh" "$what" "$ref" >&2
  docker push -q "$ref" >&2
fi
docker inspect --format '{{index .RepoDigests 0}}' "$ref"
