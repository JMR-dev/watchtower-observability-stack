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
	// CICIDRs reach SSH on the proxy's public address: the deploy runners.
	CICIDRs []string
	// BreakGlassCIDRs reach it too: the break-glass bastion's Cloud NAT
	// address (scripts/bootstrap.sh), the way in when the VPN is down and the
	// deploy's when the proxy is rebuilt. People come in over the VPN.
	BreakGlassCIDRs []string
	// BastionHostKey is the bastion's SSH host key, pinned like the hosts'.
	BastionHostKey string
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
		BastionHostKey:   r.RequiredString("bastionHostKey"),
		WireGuardCIDRs:   []string{"0.0.0.0/0", "::/0"},
		BucketPrefix:     r.RequiredString("bucketPrefix"),
		HetznerProjectID: r.RequiredInt("hetznerProjectId"),
		DeleteProtection: r.Bool("deleteProtection", false),
		GCPProject:       r.String("gcpProject", names.GCPProject),
		DNSZone:          r.String("dnsZone", "watchtower"),
	}
	r.Object("ciCidrs", &cfg.CICIDRs, true)
	r.Object("breakGlassCidrs", &cfg.BreakGlassCIDRs, true)
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
	if !sshKeyRE.MatchString(c.BastionHostKey) {
		r.Fail("bastionHostKey must be an ed25519 public key")
	}
	if len(c.CICIDRs) == 0 {
		r.Fail("ciCidrs must not be empty: the deploy reaches the hosts from there")
	}
	if len(c.BreakGlassCIDRs) == 0 {
		r.Fail("breakGlassCidrs must not be empty: the bastion reaches the proxy from there")
	}
	if len(c.WireGuardCIDRs) == 0 {
		r.Fail("wireguardAllowCidrs must not be empty")
	}
	for _, list := range [][]string{c.CICIDRs, c.BreakGlassCIDRs, c.WireGuardCIDRs} {
		for _, cidr := range list {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				r.Fail("invalid CIDR %q", cidr)
			}
		}
	}
	// SSH is never open to the world: its sources must be specific.
	for key, list := range map[string][]string{"ciCidrs": c.CICIDRs, "breakGlassCidrs": c.BreakGlassCIDRs} {
		for _, cidr := range list {
			if strings.HasSuffix(cidr, "/0") {
				r.Fail("%s must not contain %q", key, cidr)
			}
		}
	}
	if !bucketPrefixRE.MatchString(c.BucketPrefix) {
		r.Fail("bucketPrefix %q: lowercase letters, digits and dashes, 3-42 characters", c.BucketPrefix)
	}
	if c.HetznerProjectID <= 0 {
		r.Fail("hetznerProjectId must be the numeric project ID")
	}
}
