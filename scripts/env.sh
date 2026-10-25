# shellcheck shell=bash
# Exports the credentials owner-run commands need (pulumi, ansible,
# scripts/bootstrap.sh, scripts/verify.sh) from gopass, without printing any
# of them.
#
#   source scripts/env.sh
#
# gopass holds the local copy of every secret as watchtower/<id>, with the
# same ids as Secret Manager (scripts/secret.sh put writes both). CI reads
# the same values from Secret Manager instead. One entry exists only here
# and in Gitea: watchtower/gcp-deployer-key, the JSON key of
# watchtower-deployer@ (scripts/rotate-gcp-key.sh deployer), which Pulumi
# uses to read the rest.

# -o prints only an entry's first line; -n prints all of it, for key files.
_wt_get() { gopass show -o "watchtower/$1"; }
_wt_file() { gopass show -n "watchtower/$1"; }

if ! gopass ls watchtower >/dev/null 2>&1; then
  echo "gopass is locked or has no watchtower/ entries; unlock it and retry" >&2
  # shellcheck disable=SC2317 # exit only runs if the file was executed, not sourced
  return 1 2>/dev/null || exit 1
fi

export HCLOUD_TOKEN AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY PULUMI_CONFIG_PASSPHRASE
HCLOUD_TOKEN="$(_wt_get hcloud-token)"
AWS_ACCESS_KEY_ID="$(_wt_get s3-admin-access-key)"
AWS_SECRET_ACCESS_KEY="$(_wt_get s3-admin-secret-key)"
PULUMI_CONFIG_PASSPHRASE="$(_wt_get pulumi-passphrase)"
# The MinIO provider (buckets) reads the same admin key from its own names.
export MINIO_USER="$AWS_ACCESS_KEY_ID" MINIO_PASSWORD="$AWS_SECRET_ACCESS_KEY"

_wt_dir="${XDG_RUNTIME_DIR:-/tmp}/watchtower-$UID"
mkdir -p "$_wt_dir" && chmod 0700 "$_wt_dir"
if (umask 077 && _wt_file gcp-deployer-key >"$_wt_dir/gcp-deployer.json" 2>/dev/null); then
  export GOOGLE_APPLICATION_CREDENTIALS="$_wt_dir/gcp-deployer.json"
else
  rm -f "$_wt_dir/gcp-deployer.json"
  echo "no watchtower/gcp-deployer-key yet (scripts/rotate-gcp-key.sh deployer); pulumi can't read secrets until it exists" >&2
fi

# The hosts' SSH key as a 0600 file beside it too: Ansible and verify.sh use
# IdentitiesOnly, which ignores keys only the agent holds.
if (umask 077 && _wt_file ssh-private-key >"$_wt_dir/ssh-private-key" 2>/dev/null); then
  export ANSIBLE_PRIVATE_KEY_FILE="$_wt_dir/ssh-private-key"
else
  rm -f "$_wt_dir/ssh-private-key"
  echo "no watchtower/ssh-private-key; Ansible can't reach the hosts" >&2
fi
if [[ -n "${SSH_AUTH_SOCK:-}" ]]; then
  _wt_file ssh-private-key | ssh-add - >/dev/null 2>&1 || echo "could not add the hosts' SSH key to ssh-agent" >&2
fi

unset -f _wt_get _wt_file
unset _wt_dir
