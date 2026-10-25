package main

import (
	"net"
	"regexp"
	"strings"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
	"watchtower-infra/internal/stackcfg"
)

// Config is the cloud stack's configuration (namespace "watchtower").
type Config struct {
	Location    string
	NetworkZone string
	// NodeServerType is the data nodes' type (ARM cax31), ProxyServerType
	// the front box's (ARM cax11). The account's vCPU cap fits exactly 3
	// nodes and one proxy.
	NodeServerType  string
	ProxyServerType string
	// Image is resolved per architecture by Hetzner, so one name serves
	// both server types.
	Image     string
	NodeCount int
	// NodeVolumeGB and ProxyVolumeGB size each host's LUKS data volume.
	NodeVolumeGB  int
	ProxyVolumeGB int

	SSHPublicKey string
	// AdminCIDRs and CICIDRs reach SSH.
	AdminCIDRs []string
	CICIDRs    []string
	// WireGuardCIDRs reach UDP 51820 on the proxy.
	WireGuardCIDRs []string

	BucketPrefix     string
	HetznerProjectID int
	// S3AccessKeys maps names.KeyAdmin and each names.Keys entry to the
	// access key ID bucket policies name. Not config: readSecrets fills it in
	// from Secret Manager.
	S3AccessKeys map[string]string

	// DeleteProtection turns on Hetzner delete (and rebuild) protection for
	// the servers, primary IPs and volumes.
	DeleteProtection bool

	GCPProject string
	DNSZone    string
}

var (
	bucketPrefixRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,40}[a-z0-9]$`)
	sshKeyRE       = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/=]+( .*)?$`)
)

func loadConfig(ctx *pulumi.Context) (*Config, error) {
	r := stackcfg.New(ctx, "watchtower")
	cfg := &Config{
		Location:         r.String("location", "fsn1"),
		NetworkZone:      r.String("networkZone", "eu-central"),
		NodeServerType:   r.String("nodeServerType", "cax31"),
		ProxyServerType:  r.String("proxyServerType", "cax11"),
		Image:            r.String("image", "alma-10"),
		NodeCount:        r.Int("nodeCount", names.MinNodes),
		NodeVolumeGB:     r.Int("nodeVolumeGb", 30),
		ProxyVolumeGB:    r.Int("proxyVolumeGb", 10),
		SSHPublicKey:     r.RequiredString("sshPublicKey"),
		WireGuardCIDRs:   []string{"0.0.0.0/0", "::/0"},
		BucketPrefix:     r.RequiredString("bucketPrefix"),
		HetznerProjectID: r.RequiredInt("hetznerProjectId"),
		DeleteProtection: r.Bool("deleteProtection", false),
		GCPProject:       r.String("gcpProject", names.GCPProject),
		DNSZone:          r.String("dnsZone", "watchtower"),
	}
	r.Object("adminCidrs", &cfg.AdminCIDRs, true)
	r.Object("ciCidrs", &cfg.CICIDRs, false)
	r.Object("wireguardAllowCidrs", &cfg.WireGuardCIDRs, false)
	cfg.validate(r)
	return cfg, r.Err()
}

// validate fails the preview, not the apply.
func (c *Config) validate(r *stackcfg.Reader) {
	if c.NodeCount < names.MinNodes {
		r.Fail("nodeCount %d: Loki, Mimir, Kafka and etcd need at least %d nodes", c.NodeCount, names.MinNodes)
	}
	// A spread placement group holds at most 10 servers, the proxy included.
	if c.NodeCount > 9 {
		r.Fail("nodeCount %d: a spread placement group holds at most 9 nodes and the proxy", c.NodeCount)
	}
	// Hetzner volumes are 10 GB to 10 TB.
	for key, gb := range map[string]int{"nodeVolumeGb": c.NodeVolumeGB, "proxyVolumeGb": c.ProxyVolumeGB} {
		if gb < 10 || gb > 10240 {
			r.Fail("%s %d: Hetzner volumes are 10 to 10240 GB", key, gb)
		}
	}
	if !sshKeyRE.MatchString(c.SSHPublicKey) {
		r.Fail("sshPublicKey must be an ed25519 public key")
	}
	if len(c.AdminCIDRs) == 0 {
		r.Fail("adminCidrs must not be empty")
	}
	if len(c.WireGuardCIDRs) == 0 {
		r.Fail("wireguardAllowCidrs must not be empty")
	}
	for _, list := range [][]string{c.AdminCIDRs, c.CICIDRs, c.WireGuardCIDRs} {
		for _, cidr := range list {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				r.Fail("invalid CIDR %q", cidr)
			}
		}
	}
	// SSH stays closed to the world unless someone writes the open range
	// into adminCidrs on purpose; ciCidrs must be specific.
	for _, cidr := range c.CICIDRs {
		if strings.HasSuffix(cidr, "/0") {
			r.Fail("ciCidrs must not contain %q", cidr)
		}
	}
	if !bucketPrefixRE.MatchString(c.BucketPrefix) {
		r.Fail("bucketPrefix %q: lowercase letters, digits and dashes, 3-42 characters", c.BucketPrefix)
	}
	if c.HetznerProjectID <= 0 {
		r.Fail("hetznerProjectId must be the numeric project ID")
	}
}
