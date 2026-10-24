package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"strings"

	corev1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/core/v1"
	helmv4 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/helm/v4"
	metav1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/meta/v1"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"gopkg.in/yaml.v3"

	"watchtower-infra/internal/names"
)

//go:embed values/*.yaml files/*
var embedded embed.FS

// marshalYAML is swapped in tests to reach the encode-failure paths.
var marshalYAML = yaml.Marshal

// valuesFS is where chart values are read from; tests swap it to reach the
// missing-file paths.
var valuesFS fs.ReadFileFS = embedded

// loadValues returns an embedded chart values file as a map Go can amend.
func loadValues(file string) (map[string]interface{}, error) {
	raw, err := valuesFS.ReadFile("values/" + file)
	if err != nil {
		return nil, err
	}
	return parseValues(raw)
}

func parseValues(raw []byte) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := yaml.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// set writes v at a dotted path, creating (or replacing) maps on the way.
func set(m map[string]interface{}, path string, v interface{}) {
	keys := strings.Split(path, ".")
	for _, k := range keys[:len(keys)-1] {
		next, ok := m[k].(map[string]interface{})
		if !ok {
			next = map[string]interface{}{}
			m[k] = next
		}
		m = next
	}
	m[keys[len(keys)-1]] = v
}

// file returns an embedded config file.
func file(name string) string {
	// The names are constants and the files are embedded at build time; a
	// missing one fails the tests, not a deploy.
	b, _ := embedded.ReadFile("files/" + name)
	return string(b)
}

// checksum is a pod-template annotation that rolls the pods when a config
// file they mount changes.
func checksum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type namespaces struct {
	apps, edge, fip, logging pulumi.StringOutput
}

// newNamespaces creates the four namespaces with their Pod Security level.
// Only the edge pod (NET_ADMIN for WireGuard) and Fluent Bit (host log
// paths) need privileged; everything else runs restricted.
func newNamespaces(ctx *pulumi.Context, opt pulumi.ResourceOption) (*namespaces, error) {
	out := &namespaces{}
	for _, n := range []struct {
		name, level string
		dst         *pulumi.StringOutput
	}{
		{names.NamespaceApps, "restricted", &out.apps},
		{names.NamespaceEdge, "privileged", &out.edge},
		{names.NamespaceFIP, "restricted", &out.fip},
		{names.NamespaceLogging, "privileged", &out.logging},
	} {
		ns, err := corev1.NewNamespace(ctx, n.name, &corev1.NamespaceArgs{
			Metadata: &metav1.ObjectMetaArgs{
				Name: pulumi.String(n.name),
				Labels: pulumi.StringMap{
					"pod-security.kubernetes.io/enforce":         pulumi.String(n.level),
					"pod-security.kubernetes.io/enforce-version": pulumi.String("latest"),
					"pod-security.kubernetes.io/audit":           pulumi.String(n.level),
					"pod-security.kubernetes.io/warn":            pulumi.String(n.level),
				},
			},
		}, opt, pulumi.Protect(true))
		if err != nil {
			return nil, err
		}
		*n.dst = ns.Metadata.Name().Elem()
	}
	return out, nil
}

// meta is ObjectMeta with the stack's standard labels.
func meta(name string, namespace pulumi.StringInput, app string) *metav1.ObjectMetaArgs {
	return &metav1.ObjectMetaArgs{
		Name:      pulumi.String(name),
		Namespace: namespace,
		Labels:    appLabels(app),
	}
}

func appLabels(app string) pulumi.StringMap {
	return pulumi.StringMap{
		"app.kubernetes.io/name":       pulumi.String(app),
		"app.kubernetes.io/part-of":    pulumi.String("watchtower"),
		"app.kubernetes.io/managed-by": pulumi.String("pulumi"),
	}
}

// selector matches a workload's pods by name only, so adding labels later
// never changes an immutable selector.
func selector(app string) *metav1.LabelSelectorArgs {
	return &metav1.LabelSelectorArgs{MatchLabels: pulumi.StringMap{"app.kubernetes.io/name": pulumi.String(app)}}
}

// newSecret creates an Opaque Secret. Values are wrapped as secrets so they
// are encrypted in state whatever the caller passed.
func newSecret(ctx *pulumi.Context, name string, namespace pulumi.StringInput, data map[string]pulumi.StringInput,
	opts ...pulumi.ResourceOption,
) (*corev1.Secret, error) {
	sd := pulumi.StringMap{}
	for k, v := range data {
		sd[k] = pulumi.ToSecret(v).(pulumi.StringOutput)
	}
	return corev1.NewSecret(ctx, name, &corev1.SecretArgs{
		Metadata:   meta(name, namespace, name),
		Type:       pulumi.String("Opaque"),
		StringData: sd,
	}, opts...)
}

// s3Secret holds one component's S3 key as the environment variables every
// S3 client here reads when its config names no keys.
func s3Secret(ctx *pulumi.Context, cfg *Config, name, key string, namespace pulumi.StringInput,
	opts ...pulumi.ResourceOption,
) (*corev1.Secret, error) {
	k := cfg.S3Keys[key]
	return newSecret(ctx, name, namespace, map[string]pulumi.StringInput{
		"AWS_ACCESS_KEY_ID":     pulumi.String(k.AccessKey),
		"AWS_SECRET_ACCESS_KEY": pulumi.String(k.SecretKey),
	}, opts...)
}

// chart is one Helm chart, rendered client-side by the provider so every
// object it creates shows up in previews.
type chart struct {
	name, chart, version, repo string
	namespace                  pulumi.StringInput
	values                     map[string]interface{}
}

func newChart(ctx *pulumi.Context, c chart, opts ...pulumi.ResourceOption) (*helmv4.Chart, error) {
	return helmv4.NewChart(ctx, c.name, &helmv4.ChartArgs{
		Name:      pulumi.String(c.name),
		Chart:     pulumi.String(c.chart),
		Version:   pulumi.String(c.version),
		Namespace: c.namespace,
		RepositoryOpts: &helmv4.RepositoryOptsArgs{
			Repo: pulumi.String(c.repo),
		},
		Values: pulumi.ToMap(c.values),
	}, opts...)
}

// Chart repositories and versions (newest stable when written; Renovate-style
// bumps change the version here and the matching values file together).
const (
	repoGrafanaCommunity = "https://grafana-community.github.io/helm-charts"
	repoHetzner          = "https://charts.hetzner.cloud"
	repoKured            = "https://kubereboot.github.io/charts"

	versionLoki      = "19.1.1"
	versionTempo     = "3.2.1"
	versionGrafana   = "14.0.1"
	versionHcloudCSI = "2.24.0"
	versionKured     = "6.1.0"
)

// Images this program deploys itself (charts pin theirs in values/).
const (
	imageMimir     = "docker.io/grafana/mimir:3.2.3"
	imageWGEasy    = "ghcr.io/wg-easy/wg-easy:15.4.0"
	imageFluentBit = "cr.fluentbit.io/fluent/fluent-bit:5.1.5"
)

// tolerateNodeLoss evicts a pod 30s after its node stops reporting, instead
// of Kubernetes' default 300s, so the edge pod (and the Floating IP with it)
// and fipd move quickly.
func tolerateNodeLoss() corev1.TolerationArray {
	var out corev1.TolerationArray
	for _, key := range []string{"node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable"} {
		out = append(out, &corev1.TolerationArgs{
			Key:               pulumi.String(key),
			Operator:          pulumi.String("Exists"),
			Effect:            pulumi.String("NoExecute"),
			TolerationSeconds: pulumi.Int(30),
		})
	}
	return out
}

// restricted is the container security context Pod Security "restricted"
// requires.
func restricted() *corev1.SecurityContextArgs {
	return &corev1.SecurityContextArgs{
		AllowPrivilegeEscalation: pulumi.Bool(false),
		ReadOnlyRootFilesystem:   pulumi.Bool(true),
		RunAsNonRoot:             pulumi.Bool(true),
		Capabilities:             &corev1.CapabilitiesArgs{Drop: pulumi.StringArray{pulumi.String("ALL")}},
		SeccompProfile:           &corev1.SeccompProfileArgs{Type: pulumi.String("RuntimeDefault")},
	}
}
