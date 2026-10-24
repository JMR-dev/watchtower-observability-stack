# shellcheck shell=bash
# Exports the credentials owner-run commands need (pulumi, ansible,
# scripts/bootstrap.sh) from gopass, without printing any of them.
#
#   source scripts/env.sh
#
# CI gets the same values from the repo's Actions secrets instead.
# gopass paths (create them once; docs/required-secrets.md):
#   watchtower/hcloud-token          Hetzner API token (Pulumi)
#   watchtower/hcloud-ccm-token      Hetzner API token (cloud-controller-manager)
#   watchtower/s3-admin-access-key   Hetzner S3 admin key
#   watchtower/s3-admin-secret-key
#   watchtower/pulumi-passphrase     32+ random bytes
#   watchtower/gcp-dns-deployer-key  JSON key of watchtower-dns-deployer@
#   watchtower/ssh-private-key       ed25519 key for root on the nodes

_wt_get() { gopass show -o "watchtower/$1"; }

if ! gopass ls watchtower >/dev/null 2>&1; then
  echo "gopass is locked or has no watchtower/ entries; unlock it and retry" >&2
  # shellcheck disable=SC2317 # exit only runs if the file was executed, not sourced
  return 1 2>/dev/null || exit 1
fi

export HCLOUD_TOKEN HCLOUD_CCM_TOKEN AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY PULUMI_CONFIG_PASSPHRASE
HCLOUD_TOKEN="$(_wt_get hcloud-token)"
HCLOUD_CCM_TOKEN="$(_wt_get hcloud-ccm-token)"
AWS_ACCESS_KEY_ID="$(_wt_get s3-admin-access-key)"
AWS_SECRET_ACCESS_KEY="$(_wt_get s3-admin-secret-key)"
PULUMI_CONFIG_PASSPHRASE="$(_wt_get pulumi-passphrase)"
# The MinIO provider (buckets) reads the same admin key from its own names.
export MINIO_USER="$AWS_ACCESS_KEY_ID" MINIO_PASSWORD="$AWS_SECRET_ACCESS_KEY"

_wt_dir="${XDG_RUNTIME_DIR:-/tmp}/watchtower-$UID"
mkdir -p "$_wt_dir" && chmod 0700 "$_wt_dir"
(umask 077 && _wt_get gcp-dns-deployer-key >"$_wt_dir/gcp-dns-deployer.json")
export GOOGLE_APPLICATION_CREDENTIALS="$_wt_dir/gcp-dns-deployer.json"

if [[ -n "${SSH_AUTH_SOCK:-}" ]]; then
  _wt_get ssh-private-key | ssh-add - >/dev/null 2>&1 || echo "could not add the node SSH key to ssh-agent" >&2
fi

export KUBECONFIG="${KUBECONFIG_OUT:-$HOME/.kube/watchtower}"
unset -f _wt_get
unset _wt_dir
