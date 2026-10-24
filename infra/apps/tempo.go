package main

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

// newTempo installs Tempo's single binary (values/tempo.yaml) on the tempo
// bucket, with its own S3 key.
func newTempo(ctx *pulumi.Context, cfg *Config, ns *namespaces, opts ...pulumi.ResourceOption) error {
	secret, err := s3Secret(ctx, cfg, "tempo-s3", names.KeyTempo, ns.apps, opts...)
	if err != nil {
		return err
	}
	values, err := loadValues("tempo.yaml")
	if err != nil {
		return err
	}
	set(values, "tempo.storage.trace.s3.bucket", cfg.bucket("tempo"))
	_, err = newChart(ctx, chart{
		name: "tempo", chart: "tempo", version: versionTempo, repo: repoGrafanaCommunity,
		namespace: ns.apps, values: values,
	}, append(opts, pulumi.DependsOn([]pulumi.Resource{secret}))...)
	return err
}
