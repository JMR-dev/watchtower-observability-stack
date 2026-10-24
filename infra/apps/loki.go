package main

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

// newLoki installs Loki in Distributed mode (values/loki.yaml) on the loki
// bucket, with its own S3 key.
func newLoki(ctx *pulumi.Context, cfg *Config, ns *namespaces, opts ...pulumi.ResourceOption) error {
	secret, err := s3Secret(ctx, cfg, "loki-s3", names.KeyLoki, ns.apps, opts...)
	if err != nil {
		return err
	}
	values, err := lokiValues(cfg)
	if err != nil {
		return err
	}
	_, err = newChart(ctx, chart{
		name: "loki", chart: "loki", version: versionLoki, repo: repoGrafanaCommunity,
		namespace: ns.apps, values: values,
	}, append(opts, pulumi.DependsOn([]pulumi.Resource{secret}))...)
	return err
}

func lokiValues(cfg *Config) (map[string]interface{}, error) {
	values, err := loadValues("loki.yaml")
	if err != nil {
		return nil, err
	}
	bucket := cfg.bucket("loki")
	for _, use := range []string{"chunks", "ruler", "admin"} {
		set(values, "loki.storage.bucketNames."+use, bucket)
	}
	set(values, "ingester.replicas", cfg.LokiIngesters)
	set(values, "loki.commonConfig.replication_factor", cfg.LokiReplicationFactor)
	return values, nil
}
