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
	ServerType  string
	Image       string
	NodeCount   int

	SSHPublicKey string
	// AdminCIDRs and CICIDRs reach SSH and the Kubernetes API.
	AdminCIDRs []string
	CICIDRs    []string
	// WireGuardCIDRs reach UDP 51820 on every node.
	WireGuardCIDRs []string

	BucketPrefix     string
	HetznerProjectID int
	// S3AccessKeys maps "admin" and each names.Keys entry to the access key
	// ID bucket policies name. Secret: the repo is mirrored publicly.
	S3AccessKeys map[string]string

	// DeleteProtection turns on Hetzner delete (and rebuild) protection for
	// the servers, primary IPs and Floating IP.
	DeleteProtection bool

	GCPProject string
	DNSZone    string
}

// AdminKey is the S3 key Pulumi and operators use; every bucket admits it.
const AdminKey = "admin"

var (
	bucketPrefixRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,40}[a-z0-9]$`)
	sshKeyRE       = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/=]+( .*)?$`)
)

func loadConfig(ctx *pulumi.Context) (*Config, error) {
	r := stackcfg.New(ctx, "watchtower")
	cfg := &Config{
		Location:         r.String("location", "nbg1"),
		NetworkZone:      r.String("networkZone", "eu-central"),
		ServerType:       r.String("serverType", "cpx42"),
		Image:            r.String("image", "alma-10"),
		NodeCount:        r.Int("nodeCount", names.ControlPlaneNodes),
		SSHPublicKey:     r.RequiredString("sshPublicKey"),
		WireGuardCIDRs:   []string{"0.0.0.0/0", "::/0"},
		BucketPrefix:     r.RequiredString("bucketPrefix"),
		HetznerProjectID: r.RequiredInt("hetznerProjectId"),
		DeleteProtection: r.Bool("deleteProtection", false),
		GCPProject:       r.String("gcpProject", "watchtower-observe"),
		DNSZone:          r.String("dnsZone", "watchtower"),
	}
	r.Object("adminCidrs", &cfg.AdminCIDRs, true)
	r.Object("ciCidrs", &cfg.CICIDRs, false)
	r.Object("wireguardAllowCidrs", &cfg.WireGuardCIDRs, false)
	r.SecretObject("s3AccessKeys", &cfg.S3AccessKeys)
	cfg.validate(r)
	return cfg, r.Err()
}

// validate fails the preview, not the apply.
func (c *Config) validate(r *stackcfg.Reader) {
	if c.NodeCount < names.ControlPlaneNodes {
		r.Fail("nodeCount %d: etcd and the control plane need %d nodes", c.NodeCount, names.ControlPlaneNodes)
	}
	// A spread placement group holds at most 10 servers.
	if c.NodeCount > 10 {
		r.Fail("nodeCount %d: a spread placement group holds at most 10", c.NodeCount)
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
	// SSH and the API stay closed to the world unless someone writes the
	// open range into adminCidrs on purpose; ciCidrs must be specific.
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
	for _, k := range append([]string{AdminKey}, names.Keys...) {
		if c.S3AccessKeys[k] == "" {
			r.Fail("s3AccessKeys.%s is missing", k)
		}
	}
}
