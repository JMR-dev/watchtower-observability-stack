#!/usr/bin/env bash
# Validate everything infra/apps hands the cluster against the API server
# the cluster runs. CI's `manifests` job; needs go, helm, kubectl,
# kubeconform, etcd, kube-apiserver and openssl (the setup action's tools).
#
#   scripts/check-manifests.sh
#
#   1. The apps program runs under mocks (TestDumpManifests in infra/apps)
#      and writes every object it builds itself, plus each chart's values as
#      Go merged them.
#   2. helm renders each chart with those values.
#   3. kubeconform checks it all against the Kubernetes schemas.
#   4. A throwaway etcd and kube-apiserver (no scheduler or controllers, so
#      nothing runs) take a server-side apply dry run of it all, the way the
#      Pulumi provider applies it. That adds what schemas can't check: the
#      API server's own validation (an access mode a PVC can't have, a
#      duplicate list key), CRD schemas, and Pod Security. Warnings fail the
#      run, because Pod Security reports a workload's violations as warnings.
#
# Not covered: values a chart reads from a live cluster with `lookup` (they
# render empty here), changes to immutable fields of objects that already
# exist (the deploy's preview guard), and anything that only shows once pods
# run.

set -euo pipefail

# Kubespray v2.32.0's cilium_version: bump both together with Kubespray.
CILIUM_VERSION="1.20.2"
CILIUM_CNP_CRD_SHA256="62c6de8f358da125b94468d39187edb1cea157d79503fdc50ccec8a6aaa79a76"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
kube_version="$(sed -n 's/^kube_version: //p' "${repo_root}/ansible/inventory/group_vars/k8s_cluster/k8s-cluster.yml")"

work="$(mktemp -d)"
pids=()
# The API server first: without etcd its graceful shutdown never ends.
cleanup() {
  for ((i = ${#pids[@]} - 1; i >= 0; i--)); do
    kill -KILL "${pids[i]}" 2>/dev/null || true
    wait "${pids[i]}" 2>/dev/null || true
  done
  rm -rf "$work"
}
trap cleanup EXIT

if [[ "$(kube-apiserver --version)" != "Kubernetes v${kube_version}" ]]; then
  echo "kube-apiserver is $(kube-apiserver --version), the cluster runs ${kube_version}:" \
    "bump it in .gitea/actions/setup/action.yml" >&2
  exit 1
fi

echo "==> Dumping what the apps program creates"
(cd "${repo_root}/infra" && WATCHTOWER_MANIFESTS="$work" go test ./apps -run '^TestDumpManifests$' -count=1)

mkdir -p "${work}/rendered"
while IFS=$'\t' read -r name chart repo version namespace; do
  echo "==> Rendering ${name} ${version}"
  helm template "$name" "$chart" --repo "$repo" --version "$version" --namespace "$namespace" \
    --values "${work}/charts/${name}.json" >"${work}/rendered/${name}.yaml"
done <"${work}/charts.tsv"

echo "==> kubeconform against ${kube_version}"
# No schema for Cilium's policies here; the API server checks them against
# Cilium's CRD below.
kubeconform -strict -summary -kubernetes-version "$kube_version" -skip CiliumNetworkPolicy \
  "${work}/namespaces.yaml" "${work}/objects.yaml" "${work}/rendered/"*.yaml

echo "==> Starting etcd and kube-apiserver ${kube_version}"
# Off the default ports, so a local run doesn't collide with a dev cluster.
etcd --data-dir "${work}/etcd" --listen-peer-urls http://127.0.0.1:12380 \
  --listen-client-urls http://127.0.0.1:12379 --advertise-client-urls http://127.0.0.1:12379 \
  >"${work}/etcd.log" 2>&1 &
pids+=("$!")
openssl genrsa -out "${work}/sa.key" 2048 2>/dev/null
# A one-off admin token. Privileged containers and the Service range as
# Kubespray (kubeadm) sets them up. No endpoint reconciler: it refuses to
# publish a loopback address.
token="$(openssl rand -hex 32)"
echo "${token},ci,ci,system:masters" >"${work}/tokens.csv"
kube-apiserver --etcd-servers http://127.0.0.1:12379 \
  --bind-address 127.0.0.1 --advertise-address 127.0.0.1 --secure-port 16443 \
  --cert-dir "${work}/pki" --token-auth-file "${work}/tokens.csv" --authorization-mode Node,RBAC \
  --allow-privileged=true --service-cluster-ip-range 10.233.0.0/18 --endpoint-reconciler-type none \
  --service-account-issuer https://kubernetes.default.svc.cluster.local \
  --service-account-key-file "${work}/sa.key" --service-account-signing-key-file "${work}/sa.key" \
  >"${work}/apiserver.log" 2>&1 &
pids+=("$!")

export KUBECONFIG="${work}/kubeconfig"
# The API server signs its own serving certificate into the cert dir.
kubectl config set-cluster ci --server https://127.0.0.1:16443 --certificate-authority "${work}/pki/apiserver.crt" >/dev/null
kubectl config set-credentials ci --token "$token" >/dev/null
kubectl config set-context ci --cluster ci --user ci >/dev/null
kubectl config use-context ci >/dev/null
for _ in $(seq 90); do
  kubectl get --raw /readyz >/dev/null 2>&1 && break
  sleep 1
done
if ! kubectl get --raw /readyz >/dev/null 2>&1; then
  echo "kube-apiserver did not become ready:" >&2
  tail -n 40 "${work}/apiserver.log" "${work}/etcd.log" >&2
  exit 1
fi

echo "==> Creating the namespaces and Cilium's policy CRD"
curl -fsSL --retry 3 -o "${work}/cnp-crd.yaml" \
  "https://raw.githubusercontent.com/cilium/cilium/v${CILIUM_VERSION}/pkg/k8s/apis/cilium.io/client/crds/v2/ciliumnetworkpolicies.yaml"
echo "${CILIUM_CNP_CRD_SHA256}  ${work}/cnp-crd.yaml" | sha256sum -c --quiet -
kubectl create -f "${work}/cnp-crd.yaml"
kubectl apply --server-side -f "${work}/namespaces.yaml"
kubectl wait --for condition=established --timeout 60s crd/ciliumnetworkpolicies.cilium.io

dry_run() {
  kubectl apply --server-side --field-manager pulumi-kubernetes --dry-run=server --warnings-as-errors "$@"
}
echo "==> Server-side apply dry run: the program's own objects"
dry_run -f "${work}/objects.yaml"
while IFS=$'\t' read -r name _ _ _ namespace; do
  echo "==> Server-side apply dry run: ${name}"
  dry_run --namespace "$namespace" -f "${work}/rendered/${name}.yaml"
done <"${work}/charts.tsv"
