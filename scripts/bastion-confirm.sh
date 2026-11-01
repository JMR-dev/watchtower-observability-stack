#!/usr/bin/env bash
# Cancels the bastion's ruleset rollback (config/bastion/ruleset.sh): logs in
# over IAP, as the gcloud account in use, and leaves a file in the directory
# its path unit watches. A login that works is the proof that the new ruleset
# leaves the bastion reachable, so that is all this checks. Touches nothing
# else on the VM; there is nothing else an unprivileged login could do with it.
#
#   scripts/bastion-confirm.sh
#
# .gitea/workflows/bastion-confirm.yml runs it as watchtower-deployer@. For a
# service account, export CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE.
#
# The host key is pinned, as every SSH here is: HOST_KEY when set (bootstrap
# sends it, as a new VM's isn't in the stack file yet), else bastionHostKey in
# infra/cloud/Pulumi.prod.yaml. OS Login gets a fresh key for an hour, kept in
# a directory removed on exit: nothing to rotate or revoke. Needs gcloud, jq
# and ssh. Never prints a key.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stack_file="${repo_root}/infra/cloud/Pulumi.prod.yaml"

# A Go test keeps these equal to infra/internal/names.
BASTION="watchtower-bastion"
BASTION_ZONE="us-east1-b"
GCP_PROJECT="watchtower-observe"
# ruleset.sh's DROPBOX.
DROPBOX="/run/watchtower-ruleset"
# Up to 5 minutes: the VM may still be booting, and OS Login takes a moment to
# hear of a new key or a new grant.
ATTEMPTS=20
PAUSE=15

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

host_key="${HOST_KEY:-}"
if [[ -z "$host_key" ]]; then
  host_key="$(sed -n 's/^  watchtower:bastionHostKey: //p' "$stack_file")"
fi
[[ -n "$host_key" ]] || die "no host key to pin: no HOST_KEY, and no bastionHostKey in ${stack_file}"
# It comes from a dispatch's input, and goes in a known_hosts file.
[[ "$host_key" =~ ^ssh-ed25519\ [A-Za-z0-9+/]+={0,2}$ ]] || die "the host key isn't one ssh-ed25519 key"

work="$(mktemp -d)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
umask 077
printf '%s %s\n' "$BASTION" "$host_key" >"${work}/known_hosts"
unset host_key

# OS Login acts on gcloud's account, which must be the credential's: a service
# account's key file names it.
if [[ -n "${CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE:-}" ]]; then
  CLOUDSDK_CORE_ACCOUNT="$(jq -r .client_email "$CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE")"
  export CLOUDSDK_CORE_ACCOUNT
fi

key="${work}/key"
ssh-keygen -q -t ed25519 -N '' -C "watchtower-confirm $(date -u +%FT%TZ)" -f "$key"
# gcloud reports the key it added; keep that out of the output unless the call
# fails.
if ! profile="$(gcloud compute os-login ssh-keys add --key-file "${key}.pub" --ttl 1h \
  --project "$GCP_PROJECT" --format json 2>"${work}/err")"; then
  cat "${work}/err" >&2
  die "OS Login refused the key"
fi
user="$(jq -r '[.loginProfile.posixAccounts[] | select(.primary)][0].username // .loginProfile.posixAccounts[0].username' <<<"$profile")"
unset profile
[[ -n "$user" && "$user" != null ]] || die "OS Login returned no username"

cat >"${work}/ssh_config" <<EOF
Host ${BASTION}
  HostName ${BASTION}
  User ${user}
  IdentityFile ${key}
  IdentitiesOnly yes
  ProxyCommand gcloud compute start-iap-tunnel ${BASTION} 22 --listen-on-stdin --zone ${BASTION_ZONE} --project ${GCP_PROJECT} --verbosity warning
  HostKeyAlias ${BASTION}
  UserKnownHostsFile ${work}/known_hosts
  StrictHostKeyChecking yes
  BatchMode yes
  ConnectTimeout 30
EOF

for attempt in $(seq "$ATTEMPTS"); do
  if ssh -F "${work}/ssh_config" "$BASTION" "touch ${DROPBOX}/confirm"; then
    echo "confirmed: logged in to ${BASTION}, attempt ${attempt}"
    exit 0
  fi
  [[ "$attempt" -eq "$ATTEMPTS" ]] || sleep "$PAUSE"
done
die "could not log in to ${BASTION} after ${ATTEMPTS} attempts, so the rollback stands"
