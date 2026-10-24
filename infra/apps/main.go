// Command watchtower-apps deploys everything inside the Kubespray cluster:
// storage (hcloud-csi with LUKS volumes), kured, Loki, Mimir, Tempo, Grafana,
// the edge pod (wg-easy + Caddy/Coraza), fipd, the Fluent Bit log archive and
// the network policies.
//
// The cluster comes from the file KUBECONFIG names: the admin kubeconfig
// Ansible fetched. Its contents, not its path, are the provider's input, so
// a path that differs between CI and a laptop is never a provider change;
// they are a secret, encrypted in state like every other one.
package main

import (
	"encoding/json"

	"github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

var run = pulumi.Run

func main() { run(program) }

// marshalJSON is swapped in tests to reach the encode-failure paths.
var marshalJSON = json.Marshal

func program(ctx *pulumi.Context) error {
	cfg, err := loadConfig(ctx)
	if err != nil {
		return err
	}

	k8s, err := kubernetes.NewProvider(ctx, "k8s", &kubernetes.ProviderArgs{
		Kubeconfig: pulumi.ToSecret(pulumi.String(cfg.Kubeconfig)).(pulumi.StringOutput),
	})
	if err != nil {
		return err
	}
	opt := pulumi.Provider(k8s)

	ns, err := newNamespaces(ctx, opt)
	if err != nil {
		return err
	}

	csi, err := newStorage(ctx, cfg, opt)
	if err != nil {
		return err
	}
	// Everything with a volume waits for the StorageClass.
	withStorage := pulumi.DependsOn([]pulumi.Resource{csi})

	if err := newKured(ctx, opt); err != nil {
		return err
	}

	if err := newLoki(ctx, cfg, ns, opt, withStorage); err != nil {
		return err
	}
	if err := newMimir(ctx, cfg, ns, opt, withStorage); err != nil {
		return err
	}
	if err := newTempo(ctx, cfg, ns, opt, withStorage); err != nil {
		return err
	}
	if err := newGrafana(ctx, cfg, ns, opt, withStorage); err != nil {
		return err
	}
	if err := newEdge(ctx, cfg, ns, opt, withStorage); err != nil {
		return err
	}
	if err := newFipd(ctx, cfg, ns, opt); err != nil {
		return err
	}
	if err := newLogship(ctx, cfg, ns, opt); err != nil {
		return err
	}
	return newPolicies(ctx, ns, opt)
}
