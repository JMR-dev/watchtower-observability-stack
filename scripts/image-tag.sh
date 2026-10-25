#!/usr/bin/env bash
# The tag of one of our images. On Alpine: its version, the Alpine release,
# its revision and the day it was built, e.g. 15.5.0-alpine3.24.3-r1-20261025.
# Patroni, which isn't on Alpine: version and revision, 4.1.5-r1.
#
#   scripts/image-tag.sh <name>          one image's tag
#   scripts/image-tag.sh --names         every image's name, one a line
#   scripts/image-tag.sh --vars          every image's tag as Ansible extra
#                                        vars: {"watchtower_image_tags": {...}}
#   scripts/image-tag.sh --inputs        what this deploy builds on:
#                                        ALPINE_RELEASE=3.24.3
#                                        ALPINE_DIGEST=sha256:...
#                                        IMAGE_DATE=20261025 (UTC)
#   scripts/image-tag.sh --check <base>  fail if an image changed since the
#                                        commit <base> but its tag didn't
#
# The Dockerfiles take Alpine's minor release (ARG ALPINE=...alpine:3.24),
# and every build uses that minor's newest patch release, upgrading every
# package to the day's (apk upgrade). The deploy fixes both once (--inputs,
# in its guard job) and hands them to every job, so the images it builds
# and the tags it installs agree even if Alpine publishes, or the day turns,
# mid-run. Without them, this resolves them itself.
#
# The day in the tag makes the first deploy of each day (UTC) rebuild every
# Alpine image with that day's packages; the deploy runs at 05:00 UTC Monday
# to Saturday for that (deploy.yml), so the images are at most a day behind
# Alpine's package fixes, two over Sunday. Later deploys that day reuse
# those builds.
#
# Tags in Artifact Registry are immutable and a tag that's there is reused
# (scripts/publish-image.sh), so any other change to build/<name>/ needs a
# new tag, or a deploy later the same day would keep the morning's image: a
# new version (org.opencontainers.image.version), or else the next revision
# (watchtower.image.revision; back to 1 with a new version). CI's --check
# makes sure of it, and Patroni's tag has nothing else to change it.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

names() {
  local f
  for f in "${repo_root}"/build/*/Dockerfile; do basename "$(dirname "$f")"; done
}

label() { # Dockerfile text on stdin, label name: the label's value
  sed -n "s/^LABEL ${1//./\\.}=\"\([^\"]*\)\".*/\1/p" | head -1
}

# The Alpine minor release a Dockerfile builds on (3.24), or nothing.
alpine_minor() {
  sed -n 's|^ARG ALPINE=docker\.io/library/alpine:\([0-9]*\.[0-9]*\)$|\1|p' "$1" | head -1
}

# The newest patch release of the Dockerfiles' one Alpine minor, from Docker
# Hub: the X.Y.Z tag that is the same image (index digest) as X.Y.
alpine() {
  local minor tags release digest
  minor="$(for n in $(names); do alpine_minor "${repo_root}/build/${n}/Dockerfile"; done | sort -u)"
  [[ -n "$minor" ]] || die "no Dockerfile builds on Alpine (ARG ALPINE=docker.io/library/alpine:X.Y)"
  [[ "$minor" != *$'\n'* ]] || die "the Dockerfiles build on different Alpine releases: $(tr '\n' ' ' <<<"$minor")"
  tags="$(curl -fsSL --retry 3 "https://hub.docker.com/v2/namespaces/library/repositories/alpine/tags?name=${minor}&page_size=100")"
  digest="$(jq -r --arg m "$minor" '.results[] | select(.name == $m) | .digest' <<<"$tags")"
  [[ "$digest" == sha256:* ]] || die "Docker Hub has no alpine:${minor}"
  release="$(jq -r --arg m "$minor" --arg d "$digest" \
    '[.results[] | select(.digest == $d and (.name | startswith($m + ".")) and (.name | test("^[0-9]+\\.[0-9]+\\.[0-9]+$")))][0].name // empty' <<<"$tags")"
  # Hub's tags can briefly disagree while a release is being published.
  [[ -n "$release" ]] || die "alpine:${minor} (${digest}) is no alpine:${minor}.Z on Docker Hub yet; retry shortly"
  printf 'ALPINE_RELEASE=%s\nALPINE_DIGEST=%s\n' "$release" "$digest"
}

inputs() {
  alpine
  printf 'IMAGE_DATE=%s\n' "$(date -u +%Y%m%d)"
}

# The tag without its Alpine release: version and revision.
own_part() { # Dockerfile text on stdin
  local text version revision
  text="$(cat)"
  version="$(label org.opencontainers.image.version <<<"$text")"
  revision="$(label watchtower.image.revision <<<"$text")"
  [[ -n "$version" && -n "$revision" ]] || return 1
  printf '%s %s\n' "$version" "$revision"
}

tag() {
  local df="${repo_root}/build/$1/Dockerfile" version revision minor
  [[ -f "$df" ]] || die "no build/$1/Dockerfile"
  read -r version revision < <(own_part <"$df") ||
    die "build/$1/Dockerfile needs the org.opencontainers.image.version and watchtower.image.revision labels"
  [[ "$revision" =~ ^[1-9][0-9]*$ ]] || die "build/$1/Dockerfile: watchtower.image.revision must be 1, 2, ..."
  minor="$(alpine_minor "$df")"
  if [[ -z "$minor" ]]; then
    printf '%s-r%s\n' "$version" "$revision"
    return
  fi
  need_inputs
  [[ "${ALPINE_RELEASE:-}" == "${minor}".* ]] ||
    die "build/$1 builds on Alpine ${minor}, but ALPINE_RELEASE is '${ALPINE_RELEASE:-}' (scripts/image-tag.sh --inputs)"
  [[ "${IMAGE_DATE:-}" =~ ^[0-9]{8}$ ]] || die "IMAGE_DATE is '${IMAGE_DATE:-}', not YYYYMMDD"
  printf '%s-alpine%s-r%s-%s\n' "$version" "$ALPINE_RELEASE" "$revision" "$IMAGE_DATE"
}

# The Alpine tags need the release and the day; resolve them unless the
# caller did.
need_inputs() {
  [[ -n "${ALPINE_RELEASE:-}" && -n "${ALPINE_DIGEST:-}" && -n "${IMAGE_DATE:-}" ]] && return
  local out kv
  out="$(inputs)"
  while read -r kv; do export "${kv?}"; done <<<"$out"
}

check() { # base commit
  local base="$1" name old new bad=0
  git -C "$repo_root" rev-parse -q --verify "${base}^{commit}" >/dev/null || die "no commit ${base} (fetch it first)"
  for name in $(names); do
    git -C "$repo_root" diff --quiet "$base" -- "build/${name}/" && continue
    if ! old="$(git -C "$repo_root" show "${base}:build/${name}/Dockerfile" 2>/dev/null | own_part)"; then
      echo "build/${name}: new (or newly labelled) since ${base}"
      continue
    fi
    new="$(own_part <"${repo_root}/build/${name}/Dockerfile")" || die "build/${name}/Dockerfile lost its labels"
    if [[ "$old" == "$new" ]]; then
      echo "build/${name} changed since ${base} but its version and revision (${new}) didn't: bump watchtower.image.revision, or the registry keeps serving the old image under that tag" >&2
      bad=1
    else
      echo "build/${name}: ${old} -> ${new}"
    fi
  done
  return "$bad"
}

case "${1:-}" in
  --names) names ;;
  --inputs) inputs ;;
  --check) [[ $# -eq 2 ]] || die "usage: $0 --check <base-commit>"; check "$2" ;;
  --vars)
    need_inputs # once, not once per image
    while read -r name; do printf '%s\t%s\n' "$name" "$(tag "$name")"; done < <(names) |
      jq -R -s -c 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add | {watchtower_image_tags: .}'
    ;;
  "" | -*) die "usage: $0 <name> | --names | --vars | --inputs | --check <base-commit>" ;;
  *) tag "$1" ;;
esac
