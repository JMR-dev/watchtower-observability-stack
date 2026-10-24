package main

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// newStorage installs hcloud-csi. Its one StorageClass, hcloud-luks, is the
// cluster default: every PVC is a LUKS-encrypted Hetzner Volume, keyed by the
// passphrase Secret below. The CSI token is Kubespray's `hcloud` Secret.
func newStorage(ctx *pulumi.Context, cfg *Config, opt pulumi.ResourceOption) (pulumi.Resource, error) {
	luks, err := newSecret(ctx, "hcloud-luks", pulumi.String("kube-system"), map[string]pulumi.StringInput{
		"encryption-passphrase": cfg.LUKSPassphrase,
	}, opt)
	if err != nil {
		return nil, err
	}
	values, err := loadValues("hcloud-csi.yaml")
	if err != nil {
		return nil, err
	}
	return newChart(ctx, chart{
		name: "hcloud-csi", chart: "hcloud-csi", version: versionHcloudCSI, repo: repoHetzner,
		namespace: pulumi.String("kube-system"), values: values,
	}, opt, pulumi.DependsOn([]pulumi.Resource{luks}))
}

// newKured installs kured, which drains and reboots one node at a time when
// the reboot-required timer (Ansible base role) says an update needs it.
func newKured(ctx *pulumi.Context, opt pulumi.ResourceOption) error {
	values, err := loadValues("kured.yaml")
	if err != nil {
		return err
	}
	_, err = newChart(ctx, chart{
		name: "kured", chart: "kured", version: versionKured, repo: repoKured,
		namespace: pulumi.String("kube-system"), values: values,
	}, opt)
	return err
}
