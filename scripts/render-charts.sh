#!/usr/bin/env bash
# Render every chart infra/apps installs, with its values file, and validate
# the manifests against the cluster's Kubernetes version. CI's `charts` job;
# needs helm and kubeconform.
#
#   scripts/render-charts.sh
#
# Chart versions are read from infra/apps/kube.go, so there is one place they
# are spelled. The --set values stand in for what Go merges in.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
apps="${repo_root}/infra/apps"
kube_version="$(sed -n 's/^kube_version: //p' "${repo_root}/ansible/inventory/group_vars/k8s_cluster/k8s-cluster.yml")"

version() { sed -n "s/^\t$1 *= \"\(.*\)\"$/\1/p" "${apps}/kube.go"; }

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

# name|chart|repo|version|namespace|extra helm args
charts=(
  "loki|loki|https://grafana-community.github.io/helm-charts|$(version versionLoki)|watchtower|--set loki.storage.bucketNames.chunks=ci-loki --set loki.storage.bucketNames.ruler=ci-loki --set loki.storage.bucketNames.admin=ci-loki"
  "tempo|tempo|https://grafana-community.github.io/helm-charts|$(version versionTempo)|watchtower|--set tempo.storage.trace.s3.bucket=ci-tempo"
  "grafana|grafana|https://grafana-community.github.io/helm-charts|$(version versionGrafana)|watchtower|"
  "hcloud-csi|hcloud-csi|https://charts.hetzner.cloud|$(version versionHcloudCSI)|kube-system|"
  "kured|kured|https://kubereboot.github.io/charts|$(version versionKured)|kube-system|"
)

for entry in "${charts[@]}"; do
  IFS='|' read -r name chart repo ver ns extra <<<"$entry"
  [[ -n "$ver" ]] || { echo "no version for ${name} in kube.go" >&2; exit 1; }
  echo "==> ${name} ${ver}"
  # shellcheck disable=SC2086 # extra is a list of flags
  helm template "$name" "$chart" --repo "$repo" --version "$ver" --namespace "$ns" \
    --values "${apps}/values/${name}.yaml" $extra >"${out}/${name}.yaml"
  kubeconform -strict -summary -kubernetes-version "$kube_version" "${out}/${name}.yaml"
done
