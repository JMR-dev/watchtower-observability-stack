// Invariant tests under the mock runtime: no cluster, no credentials.
package main

import (
	"errors"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"gopkg.in/yaml.v3"

	"watchtower-infra/internal/names"
	"watchtower-infra/internal/pulumitest"
)

const (
	chartType  = "kubernetes:helm.sh/v4:Chart"
	secretType = "kubernetes:core/v1:Secret"
	cnpType    = "kubernetes:cilium.io/v2:CiliumNetworkPolicy"
	nsType     = "kubernetes:core/v1:Namespace"
	caddyImg   = "gitea.jasonmross.dev/jmr-dev/watchtower-caddy@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fipdImg    = "gitea.jasonmross.dev/jmr-dev/watchtower-fipd:abc123"
)

var secretKeys = []string{
	"watchtower:grafanaAdminPassword", "watchtower:wgEasyPassword", "watchtower:caddyDnsKey",
	"watchtower:luksPassphrase", "watchtower:registryToken", "watchtower:hcloudFipToken", "watchtower:s3Keys",
}

func baseConfig() map[string]string {
	cfg := map[string]string{
		"watchtower:bucketPrefix": "test-wt",
		"watchtower:caddyImage":   caddyImg,
		"watchtower:fipdImage":    fipdImg,
		"watchtower:tenants":      `[{"slug":"default","orgName":"Default"},{"slug":"team-alpha","orgName":"Team Alpha"}]`,
		"watchtower:s3Keys": `{"loki":{"accessKey":"LA","secretKey":"LS"},"mimir":{"accessKey":"MA","secretKey":"MS"},` +
			`"tempo":{"accessKey":"TA","secretKey":"TS"},"logship":{"accessKey":"GA","secretKey":"GS"}}`,
	}
	for _, k := range secretKeys[:6] {
		cfg[k] = "secret-" + k
	}
	return cfg
}

func with(extra map[string]string) map[string]string {
	cfg := baseConfig()
	for k, v := range extra {
		if v == "" {
			delete(cfg, k)
			continue
		}
		cfg[k] = v
	}
	return cfg
}

func opts(cfg map[string]string) pulumitest.Options {
	return pulumitest.Options{Project: "watchtower-apps", Stack: "prod", Config: cfg, Secrets: secretKeys}
}

func newMocks() *pulumitest.Mocks { return &pulumitest.Mocks{} }

// kubeconfig writes a stand-in kubeconfig and points KUBECONFIG at it.
func kubeconfig(t *testing.T) {
	t.Helper()
	path := t.TempDir() + "/kubeconfig"
	if err := os.WriteFile(path, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)
}

func runWith(t *testing.T, cfg map[string]string) (*pulumitest.Mocks, error) {
	t.Helper()
	kubeconfig(t)
	m := newMocks()
	return m, pulumitest.Run(t, opts(cfg), program, m)
}

func mustRun(t *testing.T) *pulumitest.Mocks {
	t.Helper()
	m, err := runWith(t, baseConfig())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// plain turns a property value into plain Go values, unwrapping secrets.
func plain(v resource.PropertyValue) interface{} {
	v = pulumitest.Unwrap(v)
	switch {
	case v.IsObject():
		out := map[string]interface{}{}
		for k, e := range v.ObjectValue() {
			out[string(k)] = plain(e)
		}
		return out
	case v.IsArray():
		var out []interface{}
		for _, e := range v.ArrayValue() {
			out = append(out, plain(e))
		}
		return out
	case v.IsString():
		return v.StringValue()
	case v.IsNumber():
		return v.NumberValue()
	case v.IsBool():
		return v.BoolValue()
	default:
		return nil
	}
}

func inputs(r pulumitest.Resource) map[string]interface{} {
	return plain(resource.NewObjectProperty(r.Inputs)).(map[string]interface{})
}

// dig follows a dotted path through maps; numeric parts index arrays.
func dig(v interface{}, path string) interface{} {
	for _, p := range strings.Split(path, ".") {
		switch c := v.(type) {
		case map[string]interface{}:
			v = c[p]
		case []interface{}:
			i := 0
			for _, ch := range p {
				i = i*10 + int(ch-'0')
			}
			if i >= len(c) {
				return nil
			}
			v = c[i]
		default:
			return nil
		}
	}
	return v
}

func resourceOf(t *testing.T, m *pulumitest.Mocks, typ, name string) map[string]interface{} {
	t.Helper()
	for _, r := range m.ByType(typ) {
		if r.Name == name {
			return inputs(r)
		}
	}
	t.Fatalf("no %s named %s", typ, name)
	return nil
}

func chartValues(t *testing.T, m *pulumitest.Mocks, name string) map[string]interface{} {
	t.Helper()
	return resourceOf(t, m, chartType, name)["values"].(map[string]interface{})
}

// containers returns every container (and init container) the program
// defines itself, keyed "<resource>/<container>".
func containers(m *pulumitest.Mocks) map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	for _, r := range m.Resources() {
		in := inputs(r)
		cs, _ := dig(in, "spec.template.spec.containers").([]interface{})
		for _, c := range cs {
			cm := c.(map[string]interface{})
			out[r.Name+"/"+cm["name"].(string)] = cm
		}
	}
	return out
}

func TestMainRunsProgram(t *testing.T) {
	var called bool
	run = func(pulumi.RunFunc, ...pulumi.RunOption) { called = true }
	t.Cleanup(func() { run = pulumi.Run })
	main()
	if !called {
		t.Error("main did not hand the program to pulumi.Run")
	}
}

func TestErrorPaths(t *testing.T) {
	kubeconfig(t)
	ignored, err := pulumitest.ErrorPaths(t, opts(baseConfig()), program, newMocks)
	if err != nil {
		t.Fatal(err)
	}
	if len(ignored) > 0 {
		t.Errorf("failures ignored: %v", ignored)
	}
}

func TestDefaultProvidersDisabled(t *testing.T) {
	b, err := os.ReadFile("Pulumi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "pulumi:disable-default-providers:\n    value: [\"*\"]") {
		t.Error("Pulumi.yaml does not disable every default provider")
	}
}

// Nothing may reach a cluster through a default provider, and the
// provider's kubeconfig (a credential) is a secret in state.
func TestExplicitProviderWithSecretKubeconfig(t *testing.T) {
	m := mustRun(t)
	for _, r := range m.Resources() {
		if strings.HasPrefix(r.Type, "pulumi:providers:") {
			kc := r.Inputs["kubeconfig"]
			if !kc.ContainsSecrets() || !strings.Contains(plain(kc).(string), "kind: Config") {
				t.Errorf("provider %s kubeconfig %v", r.Name, kc)
			}
			continue
		}
		if r.Provider == "" && r.Providers["kubernetes"] == "" {
			t.Errorf("%s (%s) has no explicit provider", r.Name, r.Type)
		}
	}
}

func TestNamespacesPodSecurity(t *testing.T) {
	m := mustRun(t)
	want := map[string]string{
		names.NamespaceApps:    "restricted",
		names.NamespaceEdge:    "privileged",
		names.NamespaceFIP:     "restricted",
		names.NamespaceLogging: "privileged",
	}
	got := m.ByType(nsType)
	if len(got) != len(want) {
		t.Fatalf("namespaces %d", len(got))
	}
	for _, r := range got {
		in := inputs(r)
		level := dig(in, "metadata.labels").(map[string]interface{})["pod-security.kubernetes.io/enforce"]
		if level != want[r.Name] {
			t.Errorf("namespace %s enforces %v, want %s", r.Name, level, want[r.Name])
		}
		if !r.Protect {
			t.Errorf("namespace %s is not protected", r.Name)
		}
	}
}

// spc_t (SELinux unconfined) is for host paths and netlink only.
func TestOnlyWireGuardAndFluentBitAreUnconfined(t *testing.T) {
	m := mustRun(t)
	var got []string
	for key, c := range containers(m) {
		if dig(c, "securityContext.seLinuxOptions.type") == "spc_t" {
			got = append(got, key)
		}
	}
	if len(got) != 2 || !contains(got, "edge/wg-easy") || !contains(got, "fluent-bit/fluent-bit") {
		t.Errorf("spc_t containers: %v", got)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestEveryImageIsPinned(t *testing.T) {
	m := mustRun(t)
	pinned := regexp.MustCompile(`^[a-z0-9.-]+/[a-z0-9._/-]+(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$`)
	for key, c := range containers(m) {
		img := c["image"].(string)
		if !pinned.MatchString(img) || strings.HasSuffix(img, ":latest") {
			t.Errorf("%s image %q is not pinned", key, img)
		}
	}
	for chart, path := range map[string]string{
		"loki":       "loki.image.tag",
		"tempo":      "tempo.tag",
		"grafana":    "image.tag",
		"kured":      "image.tag",
		"hcloud-csi": "controller.image.hcloudCSIDriver.tag",
	} {
		if tag, _ := dig(chartValues(t, m, chart), path).(string); tag == "" || tag == "latest" {
			t.Errorf("chart %s: %s = %q", chart, path, tag)
		}
	}
}

func TestSecretValuesAreSecret(t *testing.T) {
	m := mustRun(t)
	for _, r := range m.ByType(secretType) {
		if !r.Inputs["stringData"].ContainsSecrets() {
			t.Errorf("secret %s is plaintext in state", r.Name)
		}
	}
}

// The Hetzner token belongs to fipd alone: the internet-facing edge pod
// must hold no Hetzner credential.
func TestHetznerTokenOnlyInFipd(t *testing.T) {
	m := mustRun(t)
	for _, r := range m.ByType(secretType) {
		in := inputs(r)
		if _, ok := dig(in, "stringData").(map[string]interface{})["HCLOUD_TOKEN"]; !ok {
			continue
		}
		if r.Name != "fipd-hcloud" || dig(in, "metadata.namespace") != names.NamespaceFIP {
			t.Errorf("Hetzner token in %s (%v)", r.Name, dig(in, "metadata.namespace"))
		}
	}
}

func env(c map[string]interface{}) map[string]string {
	out := map[string]string{}
	list, _ := c["env"].([]interface{})
	for _, e := range list {
		em := e.(map[string]interface{})
		v, _ := em["value"].(string)
		out[em["name"].(string)] = v
	}
	return out
}

func TestEdge(t *testing.T) {
	m := mustRun(t)
	d := resourceOf(t, m, "kubernetes:apps/v1:Deployment", "edge")
	if dig(d, "spec.strategy.type") != "Recreate" || dig(d, "spec.replicas") != float64(1) {
		t.Errorf("edge strategy %v replicas %v", dig(d, "spec.strategy"), dig(d, "spec.replicas"))
	}
	tolerations := dig(d, "spec.template.spec.tolerations").([]interface{})
	if len(tolerations) != 2 || dig(tolerations[0], "tolerationSeconds") != float64(30) {
		t.Errorf("tolerations %v", tolerations)
	}
	if dig(d, "spec.template.spec.automountServiceAccountToken") != false {
		t.Error("edge pod mounts a service account token")
	}
	for _, name := range []string{"edge-wireguard", "edge-caddy"} {
		pvc := m.Named(t, name)
		if !pvc.Protect || dig(inputs(pvc), "spec.storageClassName") != storageClass {
			t.Errorf("volume %s: protect %v, %v", name, pvc.Protect, dig(inputs(pvc), "spec"))
		}
	}
	cs := containers(m)
	wg := cs["edge/wg-easy"]
	port := dig(wg, "ports.0").(map[string]interface{})
	if port["hostPort"] != float64(51820) || port["protocol"] != "UDP" {
		t.Errorf("wg-easy port %v", port)
	}
	e := env(wg)
	if e["INIT_ALLOWED_IPS"] != names.TunnelCIDR || e["HOST"] != "127.0.0.1" || e["INIT_HOST"] != names.VPNHost {
		t.Errorf("wg-easy env %v", e)
	}
	caps := dig(wg, "securityContext.capabilities.add").([]interface{})
	if len(caps) != 2 || caps[0] != "NET_ADMIN" {
		t.Errorf("wg-easy capabilities %v", caps)
	}
	caddy := cs["edge/caddy"]
	if caddy["image"] != caddyImg {
		t.Errorf("caddy image %v", caddy["image"])
	}
	if dig(caddy, "securityContext.runAsNonRoot") != true || dig(caddy, "securityContext.readOnlyRootFilesystem") != true {
		t.Errorf("caddy security context %v", caddy["securityContext"])
	}
	if env(caddy)["DOMAIN"] != names.Domain {
		t.Errorf("caddy env %v", env(caddy))
	}
}

func TestCaddyfile(t *testing.T) {
	c := file("Caddyfile")
	for _, want := range []string{
		"acme_dns googleclouddns", "SecRuleEngine DetectionOnly", "admin off",
		"{$DOMAIN}:443", "{$DOMAIN}:3100", "{$DOMAIN}:8080", "{$DOMAIN}:3200",
		"{$DOMAIN}:4317", "{$DOMAIN}:4318", "{$DOMAIN}:51821",
		"loki-distributor.watchtower.svc.cluster.local:3100",
		"loki-query-frontend.watchtower.svc.cluster.local:3100",
		"mimir.watchtower.svc.cluster.local:8080",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("Caddyfile lacks %q", want)
		}
	}
}

func TestFipd(t *testing.T) {
	m := mustRun(t)
	c := containers(m)["fipd/fipd"]
	args := strings.Join(toStrings(c["args"]), " ")
	for _, want := range []string{
		"--namespace=" + names.NamespaceEdge,
		"--selector=app.kubernetes.io/name=" + names.EdgeAppLabel,
		"--floating-ip-selector=role=" + names.FloatingIPLabel,
	} {
		if !strings.Contains(args, want) {
			t.Errorf("fipd args %q lack %q", args, want)
		}
	}
	if c["image"] != fipdImg {
		t.Errorf("fipd image %v", c["image"])
	}
	role := resourceOf(t, m, "kubernetes:rbac.authorization.k8s.io/v1:Role", "fipd-edge-pods")
	if dig(role, "metadata.namespace") != names.NamespaceEdge {
		t.Errorf("fipd role in %v", dig(role, "metadata.namespace"))
	}
}

func toStrings(v interface{}) []string {
	var out []string
	for _, e := range v.([]interface{}) {
		out = append(out, e.(string))
	}
	return out
}

func TestLokiValues(t *testing.T) {
	v := chartValues(t, mustRun(t), "loki")
	for path, want := range map[string]interface{}{
		"deploymentMode":                        "Distributed",
		"loki.auth_enabled":                     true,
		"loki.limits_config.retention_period":   "720h",
		"loki.limits_config.deletion_mode":      "filter-and-delete",
		"loki.compactor.retention_enabled":      true,
		"loki.storage.bucketNames.chunks":       "test-wt-loki",
		"loki.storage.bucketNames.ruler":        "test-wt-loki",
		"ingester.replicas":                     float64(3),
		"loki.commonConfig.replication_factor":  float64(3),
		"gateway.enabled":                       false,
		"ingester.zoneAwareReplication.enabled": false,
		"write.replicas":                        float64(0),
	} {
		if got := dig(v, path); got != want {
			t.Errorf("loki %s = %v, want %v", path, got, want)
		}
	}
	if names.RetentionLokiDays*24 != 720 {
		t.Error("loki retention constant drifted from values/loki.yaml")
	}
}

func TestMimir(t *testing.T) {
	m := mustRun(t)
	cm := resourceOf(t, m, "kubernetes:core/v1:ConfigMap", "mimir-config")
	raw := dig(cm, "data").(map[string]interface{})["mimir.yaml"].(string)
	var c map[string]interface{}
	if err := yaml.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]interface{}{
		"target":                 "all,alertmanager,overrides-exporter",
		"multitenancy_enabled":   true,
		"ingest_storage.enabled": false,
		"limits.compactor_blocks_retention_period": "90d",
		"blocks_storage.s3.bucket_name":            "test-wt-mimir-blocks",
		"ruler_storage.s3.bucket_name":             "test-wt-mimir-ruler",
		"alertmanager_storage.s3.bucket_name":      "test-wt-mimir-alertmanager",
	} {
		if got := dig(c, path); got != want {
			t.Errorf("mimir %s = %v, want %v", path, got, want)
		}
	}
	if strings.Contains(raw, "access_key") || strings.Contains(raw, "secret_access_key") {
		t.Error("mimir config carries S3 keys; they belong in the Secret")
	}
	sts := resourceOf(t, m, "kubernetes:apps/v1:StatefulSet", "mimir")
	if got := dig(sts, "spec.template.metadata.annotations").(map[string]interface{})["checksum/config"]; got != checksum(raw) {
		t.Errorf("checksum annotation %v does not track the config", got)
	}
}

func TestTempoValues(t *testing.T) {
	v := chartValues(t, mustRun(t), "tempo")
	for path, want := range map[string]interface{}{
		"tempo.storage.trace.s3.bucket": "test-wt-tempo",
		"tempo.multitenancyEnabled":     true,
		"tempo.retention":               "720h",
		"tempo.storage.trace.backend":   "s3",
	} {
		if got := dig(v, path); got != want {
			t.Errorf("tempo %s = %v, want %v", path, got, want)
		}
	}
}

func TestGrafanaDatasources(t *testing.T) {
	v := chartValues(t, mustRun(t), "grafana")
	list := dig(v, "datasources").(map[string]interface{})["datasources.yaml"].(map[string]interface{})["datasources"].([]interface{})
	if len(list) != 6 {
		t.Fatalf("want 3 datasources per tenant, got %d", len(list))
	}
	var defaults int
	for _, d := range list {
		dm := d.(map[string]interface{})
		if dm["isDefault"] == true {
			defaults++
		}
		if dig(dm, "jsonData.httpHeaderName1") != "X-Scope-OrgID" || dig(dm, "secureJsonData.httpHeaderValue1") == nil {
			t.Errorf("datasource %v does not scope by tenant", dm["name"])
		}
	}
	if defaults != 1 || dig(list[3], "secureJsonData.httpHeaderValue1") != "team-alpha" {
		t.Errorf("defaults %d, list %v", defaults, list)
	}
	if dig(v, "admin.existingSecret") != "grafana-admin" || dig(v, "initChownData.enabled") != false {
		t.Errorf("grafana values %v", v)
	}
}

func TestStorageClassEncryptedAndRetained(t *testing.T) {
	v := chartValues(t, mustRun(t), "hcloud-csi")
	sc := dig(v, "storageClasses.0").(map[string]interface{})
	params := sc["extraParameters"].(map[string]interface{})
	if sc["name"] != storageClass || sc["reclaimPolicy"] != "Retain" || sc["defaultStorageClass"] != true ||
		params["csi.storage.k8s.io/node-publish-secret-name"] != "hcloud-luks" {
		t.Errorf("storage class %v", sc)
	}
	if len(dig(v, "storageClasses").([]interface{})) != 1 {
		t.Error("an unencrypted storage class could be picked")
	}
}

func TestLogship(t *testing.T) {
	m := mustRun(t)
	conf := file("fluent-bit.conf")
	for _, want := range []string{"/var/log/containers/*.log", "Name              systemd", "kube-apiserver-audit.log", "use_put_object    On"} {
		if !strings.Contains(conf, want) {
			t.Errorf("fluent-bit.conf lacks %q", want)
		}
	}
	if strings.Count(conf, "use_put_object    On") != 3 {
		t.Error("every output must use PutObject: the archive key cannot run multipart uploads")
	}
	ds := resourceOf(t, m, "kubernetes:apps/v1:DaemonSet", "fluent-bit")
	if dig(ds, "spec.template.spec.tolerations.0.operator") != "Exists" {
		t.Error("fluent-bit does not run on every node")
	}
	c := containers(m)["fluent-bit/fluent-bit"]
	if env(c)["S3_BUCKET"] != "test-wt-logs-archive" {
		t.Errorf("fluent-bit env %v", env(c))
	}
}

func TestPoliciesDefaultDeny(t *testing.T) {
	m := mustRun(t)
	cnps := m.ByType(cnpType)
	if len(cnps) != 4 {
		t.Fatalf("want 4 policies, got %d", len(cnps))
	}
	for _, r := range cnps {
		spec := inputs(r)["spec"].(map[string]interface{})
		sel, ok := spec["endpointSelector"].(map[string]interface{})
		if !ok || len(sel) != 0 {
			t.Errorf("%s does not select every endpoint: %v", r.Name, spec["endpointSelector"])
		}
		if spec["ingress"] == nil || spec["egress"] == nil {
			t.Errorf("%s is not default-deny in both directions", r.Name)
		}
	}
	// Pod ports, not Service ports: Grafana's container listens on 3000.
	apps := resourceOf(t, m, cnpType, "cnp-watchtower")
	var edgePorts []string
	for _, p := range dig(apps, "spec.ingress.1.toPorts.0.ports").([]interface{}) {
		edgePorts = append(edgePorts, p.(map[string]interface{})["port"].(string))
	}
	if strings.Join(edgePorts, ",") != "3000,3100,8080,3200,4317,4318" {
		t.Errorf("edge may reach backend ports %v", edgePorts)
	}
	edge := resourceOf(t, m, cnpType, "cnp-edge")
	if dig(edge, "spec.ingress.0.toPorts.0.ports.0.protocol") != "UDP" || len(dig(edge, "spec.ingress").([]interface{})) != 1 {
		t.Errorf("edge ingress %v", dig(edge, "spec.ingress"))
	}
}

// The two stacks must name the same buckets.
func TestBucketPrefixMatchesCloudStack(t *testing.T) {
	prefix := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`watchtower:bucketPrefix: (\S+)`).FindSubmatch(b)
		if m == nil {
			t.Fatalf("%s has no bucketPrefix", path)
		}
		return string(m[1])
	}
	if a, c := prefix("Pulumi.prod.yaml"), prefix("../cloud/Pulumi.prod.yaml"); a != c {
		t.Errorf("apps bucketPrefix %q, cloud %q", a, c)
	}
}

func TestEncodeFailures(t *testing.T) {
	t.Run("yaml", func(t *testing.T) {
		marshalYAML = func(interface{}) ([]byte, error) { return nil, errors.New("yaml failed") }
		t.Cleanup(func() { marshalYAML = yaml.Marshal })
		if _, err := runWith(t, baseConfig()); err == nil || !strings.Contains(err.Error(), "yaml failed") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("json", func(t *testing.T) {
		orig := marshalJSON
		marshalJSON = func(interface{}) ([]byte, error) { return nil, errors.New("json failed") }
		t.Cleanup(func() { marshalJSON = orig })
		if _, err := runWith(t, baseConfig()); err == nil || !strings.Contains(err.Error(), "json failed") {
			t.Errorf("err = %v", err)
		}
	})
}

// Each component must stop on a missing values file.
func TestMissingValuesFile(t *testing.T) {
	entries, err := fs.ReadDir(embedded, "values")
	if err != nil {
		t.Fatal(err)
	}
	for _, missing := range entries {
		t.Run(missing.Name(), func(t *testing.T) {
			m := fstest.MapFS{}
			for _, e := range entries {
				if e.Name() == missing.Name() {
					continue
				}
				b, _ := embedded.ReadFile("values/" + e.Name())
				m["values/"+e.Name()] = &fstest.MapFile{Data: b}
			}
			valuesFS = m
			t.Cleanup(func() { valuesFS = embedded })
			if _, err := runWith(t, baseConfig()); err == nil || !strings.Contains(err.Error(), missing.Name()) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestParseValuesAndSet(t *testing.T) {
	if _, err := parseValues([]byte("a: [unclosed")); err == nil {
		t.Error("bad YAML parsed")
	}
	m := map[string]interface{}{"a": "scalar"}
	set(m, "a.b.c", 1)
	if dig(m, "a.b.c") != 1 {
		t.Errorf("set replaced the scalar badly: %v", m)
	}
	if dig([]interface{}{"x"}, "5") != nil || dig("leaf", "x") != nil {
		t.Error("dig out of range")
	}
}

func TestConfigValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg     map[string]string
		kube    string // "" keeps the stand-in kubeconfig
		message string
	}{
		"no kubeconfig":    {baseConfig(), "unset", "KUBECONFIG"},
		"bad kubeconfig":   {baseConfig(), "/nonexistent/kubeconfig", "KUBECONFIG"},
		"bad slug":         {with(map[string]string{"watchtower:tenants": `[{"slug":"Team_A","orgName":"A"}]`}), "", "tenant slug"},
		"duplicate slug":   {with(map[string]string{"watchtower:tenants": `[{"slug":"a","orgName":"A"},{"slug":"a","orgName":"B"}]`}), "", "listed twice"},
		"no org name":      {with(map[string]string{"watchtower:tenants": `[{"slug":"a","orgName":" "}]`}), "", "no orgName"},
		"no tenants":       {with(map[string]string{"watchtower:tenants": `[]`}), "", "tenants must not be empty"},
		"floating image":   {with(map[string]string{"watchtower:caddyImage": "caddy"}), "", "caddyImage"},
		"rf over replicas": {with(map[string]string{"watchtower:lokiReplicationFactor": "4"}), "", "lokiReplicationFactor"},
		"missing s3 key":   {with(map[string]string{"watchtower:s3Keys": `{"loki":{"accessKey":"a"}}`}), "", "s3Keys.loki"},
		"missing image":    {with(map[string]string{"watchtower:fipdImage": ""}), "", "watchtower:fipdImage"},
	} {
		t.Run(name, func(t *testing.T) {
			kubeconfig(t)
			switch tc.kube {
			case "":
			case "unset":
				t.Setenv("KUBECONFIG", "")
			default:
				t.Setenv("KUBECONFIG", tc.kube)
			}
			err := pulumitest.Run(t, opts(tc.cfg), program, newMocks())
			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Errorf("err = %v, want it to mention %q", err, tc.message)
			}
		})
	}
}
