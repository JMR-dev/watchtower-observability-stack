#!/usr/bin/env bash
# Store and check the stack's secrets. Each lives in two places: Secret
# Manager in watchtower-observe, which the deploy reads, and gopass as
# watchtower/<id>, the local copy. The ids are scripts/secret-names.txt;
# anything else is refused.
#
#   scripts/secret.sh put <id>        value from stdin (a pipe or a file), or
#                                     typed at a hidden prompt
#   scripts/secret.sh check           which secrets still lack a value or a
#                                     gopass copy; exits 1 if any do
#   scripts/secret.sh ensure <id>...  create empty secrets (bootstrap.sh does
#                                     this for every listed id)
#   scripts/secret.sh gitea <id> <NAME>
#                                     copy the latest value into the repo's
#                                     Actions secret NAME (only
#                                     registry-push-token -> REGISTRY_TOKEN
#                                     needs this; GITEA_TOKEN or prompted)
#
#   openssl rand -base64 48 | scripts/secret.sh put pulumi-passphrase
#   scripts/secret.sh put ssh-private-key <./watchtower-root
#   scripts/secret.sh put hcloud-token            # paste at the prompt
#
# A one-line value loses its trailing newline, so `echo x |` stores "x"; a
# multi-line one (a key file) is stored byte for byte. Each put adds a new
# version; the deploy reads the latest, and old versions stay in the audit
# history until `gcloud secrets versions destroy`.
#
# Secrets are created with their payload replicated to europe-west3 only
# (SECRET_LOCATION), so the values stay in the EU with everything else.
#
# The value never appears on a command line (`ps` shows those): it moves
# through a file in a 0700 temp dir that is shredded on exit.
#
# Needs gcloud logged in as the project owner, and an unlocked gopass.

set -euo pipefail

PROJECT="${GCP_PROJECT:-watchtower-observe}"
LOCATION="${SECRET_LOCATION:-europe-west3}"
GITEA_URL="${GITEA_URL:-https://gitea.jasonmross.dev}"
REPO="${GITEA_REPO:-JMR-dev/watchtower-observability-stack}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
list="${repo_root}/scripts/secret-names.txt"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
usage() { die "usage: $0 put <id> | check | ensure <id>... | gitea <id> <NAME>"; }

ids() { sed -e 's/#.*//' -e 's/[[:space:]]//g' -e '/^$/d' "$list"; }
known() { grep -qxF -- "$1" < <(ids) || die "${1} is not in scripts/secret-names.txt"; }

exists() { gcloud secrets describe "$1" --project "$PROJECT" >/dev/null 2>&1; }

api_enabled=false
ensure() {
  exists "$1" && return 0
  # A put can come before bootstrap.sh, which also enables the API.
  if [[ "$api_enabled" == false ]]; then
    gcloud services enable secretmanager.googleapis.com --project "$PROJECT" --quiet
    api_enabled=true
  fi
  gcloud secrets create "$1" --project "$PROJECT" \
    --replication-policy user-managed --locations "$LOCATION" \
    --labels app=watchtower >/dev/null
  echo "created ${1}"
}

# scratch makes the 0700 temp dir values pass through, shredded on exit.
scratch() {
  work="$(mktemp -d)"
  chmod 0700 "$work"
  trap 'find "$work" -type f -exec shred -u {} + 2>/dev/null; rm -rf "$work"' EXIT
  umask 077
}

put() {
  local id=$1 value
  scratch

  if [[ -t 0 ]]; then
    read -rsp "Value for ${id}: " value
    echo
    printf '%s' "$value" >"${work}/value"
    unset value
  else
    cat >"${work}/value"
  fi
  [[ -s "${work}/value" ]] || die "empty value; nothing stored"
  if [[ "$(wc -l <"${work}/value")" -le 1 ]]; then
    value="$(cat "${work}/value")"
    printf '%s' "$value" >"${work}/value"
    unset value
  fi

  ensure "$id"
  gcloud secrets versions add "$id" --project "$PROJECT" --data-file "${work}/value" >/dev/null
  if ! gopass insert -f "watchtower/${id}" <"${work}/value" >/dev/null; then
    die "${id} is in Secret Manager, but the gopass copy failed; rerun once gopass is unlocked"
  fi
  echo "stored ${id} in Secret Manager (${PROJECT}) and gopass (watchtower/${id})"
}

gitea() {
  local id=$1 name=$2 status
  scratch
  if [[ -z "${GITEA_TOKEN:-}" ]]; then
    read -rsp "Gitea token with write access to ${REPO}: " GITEA_TOKEN
    echo
  fi
  printf 'Authorization: token %s\n' "$GITEA_TOKEN" >"${work}/auth-header"
  unset GITEA_TOKEN
  gcloud secrets versions access latest --secret "$id" --project "$PROJECT" --out-file "${work}/value"
  jq -n --rawfile data "${work}/value" '{data: $data}' >"${work}/body.json"
  status="$(curl -sS -o "${work}/response" -w '%{http_code}' -X PUT \
    -H @"${work}/auth-header" -H 'Content-Type: application/json' \
    --data @"${work}/body.json" \
    "${GITEA_URL}/api/v1/repos/${REPO}/actions/secrets/${name}")"
  if [[ "$status" != 201 && "$status" != 204 ]]; then
    cat "${work}/response" >&2 || true
    die "Gitea returned HTTP ${status}"
  fi
  echo "copied ${id} to the Actions secret ${name} on ${REPO}"
}

check() {
  local id local_ids bad=0
  local_ids="$(gopass ls --flat watchtower 2>/dev/null || true)"
  while read -r id; do
    if ! exists "$id"; then
      echo "missing  ${id}: no such secret (scripts/bootstrap.sh)"
      bad=1
    elif [[ -z "$(gcloud secrets versions list "$id" --project "$PROJECT" \
      --filter state=ENABLED --limit 1 --format 'value(name)')" ]]; then
      echo "empty    ${id}: no enabled version (scripts/secret.sh put ${id})"
      bad=1
    fi
    if ! grep -qxF "watchtower/${id}" <<<"$local_ids"; then
      echo "no copy  ${id}: not in gopass as watchtower/${id}"
      bad=1
    fi
  done < <(ids)
  [[ "$bad" == 0 ]] && echo "every secret has a value in Secret Manager and a gopass copy"
  return "$bad"
}

[[ $# -ge 1 ]] || usage
case "$1" in
  put)
    [[ $# -eq 2 ]] || usage
    known "$2"
    put "$2"
    ;;
  check)
    [[ $# -eq 1 ]] || usage
    check
    ;;
  ensure)
    [[ $# -ge 2 ]] || usage
    shift
    for id in "$@"; do known "$id"; done
    for id in "$@"; do ensure "$id"; done
    ;;
  gitea)
    [[ $# -eq 3 && "$3" =~ ^[A-Z][A-Z0-9_]*$ ]] || usage
    known "$2"
    gitea "$2" "$3"
    ;;
  *) usage ;;
esac
