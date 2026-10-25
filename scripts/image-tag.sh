#!/usr/bin/env bash
# The tag of one of our images: its version, the Alpine release it's built
# on, and its revision, e.g. 15.5.0-alpine3.24.3-r1 (2.11.7 ... for Caddy,
# 4.1.5-r1 for Patroni, which isn't on Alpine).
#
#   scripts/image-tag.sh <name>          one image's tag
#   scripts/image-tag.sh --names         every image's name, one a line
#   scripts/image-tag.sh --vars          every image's tag as Ansible extra
#                                        vars: {"watchtower_image_tags": {...}}
#   scripts/image-tag.sh --alpine        the Alpine release to build on:
#                                        ALPINE_RELEASE=3.24.3
#                                        ALPINE_DIGEST=sha256:...
#   scripts/image-tag.sh --check <base>  fail if an image changed since the
#                                        commit <base> but its tag didn't
#
# The Dockerfiles take Alpine's minor release (ARG ALPINE=...alpine:3.24),
# and every build uses that minor's newest patch release: the deploy resolves
# it once (--alpine, in its guard job) and hands ALPINE_RELEASE and
# ALPINE_DIGEST to every job, so the images it builds and the tags it
# installs agree even if Alpine publishes mid-run. Without them, this
# resolves the release itself. A new Alpine patch release changes every
# Alpine image's tag, so the next deploy rebuilds them all on it.
#
# Tags in Artifact Registry are immutable and a tag that's there is reused
# (scripts/publish-image.sh), so any other change to build/<name>/ needs a
# new tag: a new version (org.opencontainers.image.version), or else the
# next revision (watchtower.image.revision; back to 1 with a new version).
# CI's --check makes sure of it.

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
  need_alpine
  [[ "${ALPINE_RELEASE:-}" == "${minor}".* ]] ||
    die "build/$1 builds on Alpine ${minor}, but ALPINE_RELEASE is '${ALPINE_RELEASE:-}' (scripts/image-tag.sh --alpine)"
  printf '%s-alpine%s-r%s\n' "$version" "$ALPINE_RELEASE" "$revision"
}

# The Alpine tags need the release; resolve it unless the caller did.
need_alpine() {
  [[ -n "${ALPINE_RELEASE:-}" ]] && return
  local out kv
  out="$(alpine)"
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
  --alpine) alpine ;;
  --check) [[ $# -eq 2 ]] || die "usage: $0 --check <base-commit>"; check "$2" ;;
  --vars)
    need_alpine # once, not once per image
    while read -r name; do printf '%s\t%s\n' "$name" "$(tag "$name")"; done < <(names) |
      jq -R -s -c 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add | {watchtower_image_tags: .}'
    ;;
  "" | -*) die "usage: $0 <name> | --names | --vars | --alpine | --check <base-commit>" ;;
  *) tag "$1" ;;
esac
