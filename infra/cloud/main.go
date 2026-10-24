// Command watchtower-cloud provisions the Hetzner side of the stack: the
// private network, three (or more) AlmaLinux nodes behind one firewall, the
// VPN Floating IP, and the telemetry and log-archive buckets. It also writes
// the three records in the Cloud DNS zone watchtower.jasonmross.dev.
//
// What it hands on: the Ansible inventory Kubespray builds the cluster from.
// Everything inside the cluster belongs to ../apps.
//
// Credentials come from the environment, never from stack config, so none of
// them lands in state: HCLOUD_TOKEN (hcloud), MINIO_USER / MINIO_PASSWORD (the
// admin S3 key) and GOOGLE_APPLICATION_CREDENTIALS (a key whose only grant is
// dns.admin on the one zone).
package main

import (
	"encoding/json"
	"strconv"

	gcp "github.com/pulumi/pulumi-gcp/sdk/v10/go/gcp"
	"github.com/pulumi/pulumi-hcloud/sdk/go/hcloud"
	"github.com/pulumi/pulumi-minio/sdk/go/minio"
	"github.com/pulumi/pulumi-tls/sdk/v5/go/tls"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

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

	net, err := newNetwork(ctx, cfg, p)
	if err != nil {
		return err
	}

	nodes, err := newNodes(ctx, cfg, p, net)
	if err != nil {
		return err
	}

	fip, err := newFloatingIP(ctx, cfg, p, nodes[0])
	if err != nil {
		return err
	}

	buckets, err := newBuckets(ctx, cfg, p)
	if err != nil {
		return err
	}

	if err := newRecords(ctx, cfg, p, nodes, fip); err != nil {
		return err
	}

	ctx.Export("inventory", inventoryJSON(cfg, nodes, fip))
	ctx.Export("knownHosts", knownHosts(nodes))
	ctx.Export("floatingIpv4", fip.IpAddress)
	ctx.Export("buckets", buckets)
	ctx.Export("s3Endpoint", pulumi.String("https://"+names.S3Endpoint))
	nodeIPs := pulumi.StringMap{}
	for _, n := range nodes {
		nodeIPs[n.name] = n.server.Ipv4Address
	}
	ctx.Export("nodeIpv4s", nodeIPs)
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
	// Generates the nodes' SSH host keys, locally.
	t, err := tls.NewProvider(ctx, "tls", &tls.ProviderArgs{})
	if err != nil {
		return nil, err
	}
	return &providers{hcloud: hc, s3: s3, gcp: g, tls: t}, nil
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
