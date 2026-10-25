#!/usr/bin/env bash
# Build, check, scan and push one of our images to Artifact Registry, unless
# its tag is already there.
#
#   GAR_PUSH_KEY=<json> scripts/publish-image.sh <name>
#
# The tag is the image's version, Alpine release and revision
# (scripts/image-tag.sh), and tags in the repo are immutable
# (scripts/bootstrap.sh), so a tag that exists is this image, already checked
# and scanned: it is reused, not rebuilt. deploy.yml runs it on the arm64
# runner, for each image, with the Alpine release its guard job resolved
# (ALPINE_RELEASE, ALPINE_DIGEST); without them it resolves the release
# itself. The key can write only to that one repo. Prints the pushed image's
# reference by digest.

set -euo pipefail

REGISTRY="${REGISTRY:-europe-west3-docker.pkg.dev}"
REPO="${REPO:-${REGISTRY}/watchtower-observe/watchtower}"

[[ $# -eq 1 ]] || { echo "usage: $0 <name>" >&2; exit 1; }
what="$1"
[[ -n "${GAR_PUSH_KEY:-}" ]] || { echo "GAR_PUSH_KEY is not set" >&2; exit 1; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# One Alpine release for the tag and the build.
if [[ -z "${ALPINE_RELEASE:-}" || -z "${ALPINE_DIGEST:-}" ]]; then
  alpine="$("${repo_root}/scripts/image-tag.sh" --alpine)"
  while read -r kv; do export "${kv?}"; done <<<"$alpine"
fi
ref="${REPO}/${what}:$("${repo_root}/scripts/image-tag.sh" "$what")"

# The key goes in on stdin; docker keeps it in its config until the job's
# cleanup step removes it.
printf '%s' "$GAR_PUSH_KEY" | docker login -u _json_key --password-stdin "https://${REGISTRY}" >/dev/null

if docker pull -q "$ref" >/dev/null 2>&1; then
  echo "${ref} is already there, checked and scanned" >&2
else
  "${repo_root}/scripts/build-image.sh" "$what" "$ref" >&2
  docker push -q "$ref" >&2
fi
docker inspect --format '{{index .RepoDigests 0}}' "$ref"
