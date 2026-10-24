package main

import (
	"os"
	"regexp"
	"strings"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
	"watchtower-infra/internal/stackcfg"
)

// Tenant is one Grafana org and X-Scope-OrgID.
type Tenant struct {
	Slug    string `json:"slug"`
	OrgName string `json:"orgName"`
}

// S3Key is one component's Hetzner S3 credential.
type S3Key struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
}

// Config is the apps stack's configuration (namespace "watchtower").
type Config struct {
	// BucketPrefix must match the cloud stack's.
	BucketPrefix string
	Tenants      []Tenant

	// CaddyImage and FipdImage are set by CI to the digest it just built.
	CaddyImage   string
	FipdImage    string
	RegistryUser string

	LokiIngesters         int
	LokiReplicationFactor int

	// Kubeconfig is the contents of the file KUBECONFIG names.
	Kubeconfig string

	// Secrets: plaintext in memory only; everything built from them is
	// wrapped with pulumi.ToSecret.
	S3Keys map[string]S3Key

	GrafanaAdminPassword pulumi.StringOutput
	WGEasyPassword       pulumi.StringOutput
	CaddyDNSKey          pulumi.StringOutput
	LUKSPassphrase       pulumi.StringOutput
	RegistryToken        pulumi.StringOutput
	HcloudFipToken       pulumi.StringOutput
}

var (
	tenantSlugRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)
	// imageRE requires a registry path and either a tag or a digest.
	imageRE = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$`)
)

func loadConfig(ctx *pulumi.Context) (*Config, error) {
	r := stackcfg.New(ctx, "watchtower")
	cfg := &Config{
		BucketPrefix:          r.RequiredString("bucketPrefix"),
		Tenants:               []Tenant{{Slug: "default", OrgName: "Default"}},
		CaddyImage:            r.RequiredString("caddyImage"),
		FipdImage:             r.RequiredString("fipdImage"),
		RegistryUser:          r.String("registryUser", "JMR-dev"),
		LokiIngesters:         r.Int("lokiIngesters", 3),
		LokiReplicationFactor: r.Int("lokiReplicationFactor", 3),
		GrafanaAdminPassword:  r.Secret("grafanaAdminPassword"),
		WGEasyPassword:        r.Secret("wgEasyPassword"),
		CaddyDNSKey:           r.Secret("caddyDnsKey"),
		LUKSPassphrase:        r.Secret("luksPassphrase"),
		RegistryToken:         r.Secret("registryToken"),
		HcloudFipToken:        r.Secret("hcloudFipToken"),
	}
	r.Object("tenants", &cfg.Tenants, false)
	r.SecretObject("s3Keys", &cfg.S3Keys)
	cfg.validate(r)
	return cfg, r.Err()
}

// validate fails the preview, not the apply.
func (c *Config) validate(r *stackcfg.Reader) {
	// Explicitly KUBECONFIG, never ~/.kube/config and whatever context
	// happens to be current there.
	path := os.Getenv("KUBECONFIG")
	if b, err := os.ReadFile(path); path == "" || err != nil {
		r.Fail("KUBECONFIG must name the watchtower cluster's kubeconfig (%q)", path)
	} else {
		c.Kubeconfig = string(b)
	}
	if len(c.Tenants) == 0 {
		r.Fail("tenants must not be empty")
	}
	seen := map[string]bool{}
	for _, t := range c.Tenants {
		if !tenantSlugRE.MatchString(t.Slug) {
			r.Fail("tenant slug %q: lowercase letters, digits and dashes, at most 40", t.Slug)
		}
		if seen[t.Slug] {
			r.Fail("tenant slug %q is listed twice", t.Slug)
		}
		seen[t.Slug] = true
		if strings.TrimSpace(t.OrgName) == "" {
			r.Fail("tenant %q has no orgName", t.Slug)
		}
	}
	for key, image := range map[string]string{"caddyImage": c.CaddyImage, "fipdImage": c.FipdImage} {
		if !imageRE.MatchString(image) {
			r.Fail("%s %q must be a registry path with a tag or digest", key, image)
		}
	}
	if c.LokiReplicationFactor < 1 || c.LokiReplicationFactor > c.LokiIngesters {
		r.Fail("lokiReplicationFactor %d must be between 1 and lokiIngesters (%d)", c.LokiReplicationFactor, c.LokiIngesters)
	}
	for _, k := range names.Keys {
		if c.S3Keys[k].AccessKey == "" || c.S3Keys[k].SecretKey == "" {
			r.Fail("s3Keys.%s needs accessKey and secretKey", k)
		}
	}
}

// bucket returns the full name of a names.Buckets entry.
func (c *Config) bucket(suffix string) string {
	return names.BucketName(c.BucketPrefix, suffix)
}
