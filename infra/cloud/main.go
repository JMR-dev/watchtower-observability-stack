// Command watchtower-cloud provisions the Hetzner side of the stack: the
// private network, the proxy (ARM, Caddy and the WireGuard endpoint) and three
// (or more) ARM data nodes, each with its own data volume, the two firewalls,
// and the telemetry and log-archive buckets. It also writes the two records in
// the Cloud DNS zone watchtower.jasonmross.dev.
//
// What it hands on: the Ansible inventory (../../ansible) that installs
// everything on the hosts, as podman quadlets.
//
// Credentials come from the environment, never from stack config, so none of
// them lands in state: HCLOUD_TOKEN (hcloud), MINIO_USER / MINIO_PASSWORD (the
// admin S3 key) and GOOGLE_APPLICATION_CREDENTIALS (watchtower-deployer@,
// whose grants are dns.admin on the one zone and read access to each of the
// stack's secrets). The S3 access key IDs the bucket policies name come from
// Secret Manager.
package main

import (
	"encoding/json"
	"strconv"

	gcp "github.com/pulumi/pulumi-gcp/sdk/v10/go/gcp"
	"github.com/pulumi/pulumi-hcloud/sdk/go/hcloud"
	"github.com/pulumi/pulumi-minio/sdk/go/minio"
	"github.com/pulumi/pulumi-tls/sdk/v5/go/tls"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/gsm"
	"watchtower-infra/internal/names"
)

var run = pulumi.Run

func main() { run(program) }

// marshalJSON is swapped in tests to reach the encode-failure paths.
var marshalJSON = json.Marshal

type providers struct {
	hcloud *hcloud.Provider
	s3     *minio.Provider
	gcp    *gcp.Provider
	tls    *tls.Provider
}

func program(ctx *pulumi.Context) error {
	cfg, err := loadConfig(ctx)
	if err != nil {
		return err
	}

	p, err := newProviders(ctx, cfg)
	if err != nil {
		return err
	}

	if err := readSecrets(ctx, cfg, p); err != nil {
		return err
	}

	net, err := newNetwork(ctx, cfg, p)
	if err != nil {
		return err
	}

	hs, err := newHosts(ctx, cfg, p, net)
	if err != nil {
		return err
	}

	buckets, err := newBuckets(ctx, cfg, p)
	if err != nil {
		return err
	}

	if err := newRecords(ctx, cfg, p, hs.proxy); err != nil {
		return err
	}

	ctx.Export("inventory", inventoryJSON(cfg, hs))
	ctx.Export("knownHosts", knownHosts(hs.all()))
	ctx.Export("proxyIpv4", hs.proxy.server.Ipv4Address)
	ctx.Export("buckets", buckets)
	ctx.Export("s3Endpoint", pulumi.String("https://"+names.S3Endpoint))
	hostIPs := pulumi.StringMap{}
	for _, h := range hs.all() {
		hostIPs[h.name] = h.server.Ipv4Address
	}
	ctx.Export("hostIpv4s", hostIPs)
	return nil
}

func newProviders(ctx *pulumi.Context, cfg *Config) (*providers, error) {
	// Token from HCLOUD_TOKEN.
	hc, err := hcloud.NewProvider(ctx, "hcloud", &hcloud.ProviderArgs{})
	if err != nil {
		return nil, err
	}
	// Credentials from MINIO_USER / MINIO_PASSWORD (the admin S3 key).
	s3, err := minio.NewProvider(ctx, "hetzner-s3", &minio.ProviderArgs{
		MinioServer: pulumi.String(names.S3Endpoint),
		MinioRegion: pulumi.String(names.S3Region),
		MinioSsl:    pulumi.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	// Credentials from GOOGLE_APPLICATION_CREDENTIALS.
	g, err := gcp.NewProvider(ctx, "gcp", &gcp.ProviderArgs{
		Project: pulumi.String(cfg.GCPProject),
	})
	if err != nil {
		return nil, err
	}
	// Generates the hosts' SSH host keys, locally.
	t, err := tls.NewProvider(ctx, "tls", &tls.ProviderArgs{})
	if err != nil {
		return nil, err
	}
	return &providers{hcloud: hc, s3: s3, gcp: g, tls: t}, nil
}

// readSecrets fills in the access key IDs the bucket policies name: the admin
// key's and the cluster key's.
func readSecrets(ctx *pulumi.Context, cfg *Config, p *providers) error {
	r := gsm.New(ctx, cfg.GCPProject, p.gcp)
	cfg.S3AccessKeys = map[string]string{}
	for _, k := range append([]string{names.KeyAdmin}, names.Keys...) {
		cfg.S3AccessKeys[k] = r.Plain(names.S3AccessKeySecret(k))
	}
	return r.Err()
}

// intID turns a Hetzner resource's Pulumi ID into the integer the API uses to
// reference it.
func intID(id pulumi.IDOutput) pulumi.IntOutput {
	return id.ApplyT(func(v pulumi.ID) (int, error) {
		return strconv.Atoi(string(v))
	}).(pulumi.IntOutput)
}

func labels(extra map[string]string) pulumi.StringMap {
	m := pulumi.StringMap{
		"app":        pulumi.String("watchtower"),
		"managed-by": pulumi.String("pulumi"),
	}
	for k, v := range extra {
		m[k] = pulumi.String(v)
	}
	return m
}
