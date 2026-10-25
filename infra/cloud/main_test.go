// Invariant tests under the mock runtime: no cloud calls, no credentials.
package main

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
	"watchtower-infra/internal/pulumitest"
)

const (
	serverType     = "hcloud:index/server:Server"
	firewallType   = "hcloud:index/firewall:Firewall"
	fipType        = "hcloud:index/floatingIp:FloatingIp"
	volumeType     = "hcloud:index/volume:Volume"
	attachmentType = "hcloud:index/volumeAttachment:VolumeAttachment"
	hostKeyType    = "tls:index/privateKey:PrivateKey"
	hostPrivate    = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----\n"
	hostPublic     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKey\n"
	bucketType     = "minio:index/s3Bucket:S3Bucket"
	policyType     = "minio:index/s3BucketPolicy:S3BucketPolicy"
	ilmType        = "minio:index/ilmPolicy:IlmPolicy"
	recordType     = "gcp:dns/recordSet:RecordSet"
	zoneToken      = "gcp:dns/getManagedZone:getManagedZone"
	secretToken    = "gcp:secretmanager/getSecretVersionAccess:getSecretVersionAccess"
	nodeAddress    = "203.0.113.10"
	proxyAddress   = "198.51.100.7"
)

func baseConfig() map[string]string {
	cfg := map[string]string{
		"watchtower:sshPublicKey":     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest test@example",
		"watchtower:bucketPrefix":     "test-wt",
		"watchtower:hetznerProjectId": "1234",
		"watchtower:ciCidrs":          `["34.26.149.196/32"]`,
		"watchtower:breakGlassCidrs":  `["35.231.222.153/32"]`,
	}
	// Any ed25519 public key will do for the bastion's.
	cfg["watchtower:bastionHostKey"] = cfg["watchtower:sshPublicKey"]
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

// secretValue is what the mocked Secret Manager holds: s3-cluster-access-key
// is "CLUSTERKEY", s3-admin-access-key "ADMINKEY".
func secretValue(id string) string {
	key := strings.TrimSuffix(strings.TrimPrefix(id, "s3-"), "-access-key")
	return strings.ToUpper(key) + "KEY"
}

// newMocks hands out numeric IDs (Hetzner references resources by integer),
// gives the proxy its own address, and answers the zone and secret lookups.
func newMocks(dnsName string) func() *pulumitest.Mocks {
	return func() *pulumitest.Mocks {
		var mu sync.Mutex
		next := 100
		return &pulumitest.Mocks{
			ID: func(typ, name string) string {
				mu.Lock()
				defer mu.Unlock()
				next++
				return strconv.Itoa(next)
			},
			Outputs: map[string]resource.PropertyMap{
				serverType: {"ipv4Address": resource.NewStringProperty(nodeAddress)},
				hostKeyType: {
					"privateKeyOpenssh": resource.NewStringProperty(hostPrivate),
					"publicKeyOpenssh":  resource.NewStringProperty(hostPublic),
				},
			},
			NamedOutputs: map[string]resource.PropertyMap{
				names.ProxyName: {"ipv4Address": resource.NewStringProperty(proxyAddress)},
			},
			Calls: map[string]pulumitest.CallFunc{
				zoneToken: func(resource.PropertyMap) (resource.PropertyMap, error) {
					return resource.PropertyMap{
						"name":    resource.NewStringProperty("watchtower"),
						"dnsName": resource.NewStringProperty(dnsName),
					}, nil
				},
				secretToken: func(args resource.PropertyMap) (resource.PropertyMap, error) {
					v := secretValue(pulumitest.Str(args, "secret"))
					return resource.PropertyMap{"secretData": resource.NewStringProperty(v)}, nil
				},
			},
		}
	}
}

var goodZone = newMocks(names.Domain + ".")

func runWith(t *testing.T, cfg map[string]string, program pulumi.RunFunc) (*pulumitest.Mocks, error) {
	t.Helper()
	m := goodZone()
	err := pulumitest.Run(t, opts(cfg), program, m)
	return m, err
}

func opts(cfg map[string]string) pulumitest.Options {
	return pulumitest.Options{
		Project: "watchtower-cloud",
		Stack:   "prod",
		Config:  cfg,
	}
}

func mustRun(t *testing.T, cfg map[string]string) *pulumitest.Mocks {
	t.Helper()
	m, err := runWith(t, cfg, program)
	if err != nil {
		t.Fatal(err)
	}
	return m
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

// Every resource registration and lookup failure must reach the engine.
func TestErrorPaths(t *testing.T) {
	ignored, err := pulumitest.ErrorPaths(t, opts(baseConfig()), program, goodZone)
	if err != nil {
		t.Fatal(err)
	}
	if len(ignored) > 0 {
		t.Errorf("failures ignored: %v", ignored)
	}
}

// pulumi:disable-default-providers keeps a resource that forgot its provider
// from silently using one configured from the environment.
func TestDefaultProvidersDisabled(t *testing.T) {
	b, err := os.ReadFile("Pulumi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "pulumi:disable-default-providers:\n    value: [\"*\"]") {
		t.Error("Pulumi.yaml does not disable every default provider")
	}
}

func TestEveryResourceHasExplicitProvider(t *testing.T) {
	m := mustRun(t, baseConfig())
	for _, r := range m.Resources() {
		if strings.HasPrefix(r.Type, "pulumi:providers:") {
			continue
		}
		if r.Provider == "" {
			t.Errorf("%s (%s) has no explicit provider", r.Name, r.Type)
		}
	}
}

// No credential may be passed to a provider as an input: inputs land in state.
func TestProvidersTakeNoCredentials(t *testing.T) {
	m := mustRun(t, baseConfig())
	for _, r := range m.Resources() {
		if !strings.HasPrefix(r.Type, "pulumi:providers:") {
			continue
		}
		for k := range r.Inputs {
			key := strings.ToLower(string(k))
			for _, bad := range []string{"token", "password", "secret", "credentials", "user"} {
				if strings.Contains(key, bad) {
					t.Errorf("provider %s takes %s as an input", r.Name, k)
				}
			}
		}
	}
}

// ports maps each rule's port (or protocol, for portless rules) to its
// sources.
func ports(r pulumitest.Resource) map[string][]string {
	out := map[string][]string{}
	for _, v := range r.Inputs["rules"].ArrayValue() {
		rule := v.ObjectValue()
		key := pulumitest.Str(rule, "protocol") + "/" + pulumitest.Str(rule, "port")
		for _, s := range rule["sourceIps"].ArrayValue() {
			out[key] = append(out[key], s.StringValue())
		}
	}
	return out
}

// SSH only to the proxy and only from the deploy runners; WireGuard on the
// proxy only; nothing else from the internet.
func TestFirewalls(t *testing.T) {
	m := mustRun(t, baseConfig())
	fws := map[string]pulumitest.Resource{}
	for _, fw := range m.ByType(firewallType) {
		fws[fw.Name] = fw
	}
	if len(fws) != 2 {
		t.Fatalf("want two firewalls, got %v", keysOf(fws))
	}
	ssh := []string{"34.26.149.196/32", "35.231.222.153/32"}
	world := []string{"0.0.0.0/0", "::/0"}
	for name, want := range map[string]struct {
		role  string
		rules map[string][]string
	}{
		// No public SSH on the nodes; the proxy's only from the deploy
		// runners and the bastion.
		"watchtower-nodes": {names.RoleNode, map[string][]string{"icmp/": world}},
		"watchtower-proxy": {names.RoleProxy, map[string][]string{"tcp/22": ssh, "udp/51820": world, "icmp/": world}},
	} {
		fw := fws[name]
		if got := ports(fw); !reflect.DeepEqual(got, want.rules) {
			t.Errorf("%s rules %v, want %v", name, got, want.rules)
		}
		applies := fw.Inputs["applyTos"].ArrayValue()
		if len(applies) != 1 || pulumitest.Str(applies[0].ObjectValue(), "labelSelector") != "role="+want.role {
			t.Errorf("%s applies to %v", name, applies)
		}
	}
}

func keysOf[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedServers(m *pulumitest.Mocks) []pulumitest.Resource {
	servers := m.ByType(serverType)
	// Registration is asynchronous, so the mocks see servers in any order.
	sort.Slice(servers, func(a, b int) bool { return servers[a].Name < servers[b].Name })
	return servers
}

func TestServers(t *testing.T) {
	m := mustRun(t, with(map[string]string{"watchtower:nodeCount": "4", "watchtower:deleteProtection": "true"}))
	servers := sortedServers(m)
	// watchtower-1..4 sort before watchtower-proxy.
	want := []struct{ name, typ, role, ip string }{
		{"watchtower-1", "cax31", names.RoleNode, names.PrivateIP(1)},
		{"watchtower-2", "cax31", names.RoleNode, names.PrivateIP(2)},
		{"watchtower-3", "cax31", names.RoleNode, names.PrivateIP(3)},
		{"watchtower-4", "cax31", names.RoleNode, names.PrivateIP(4)},
		{names.ProxyName, "cax11", names.RoleProxy, names.PrivateIP(0)},
	}
	if len(servers) != len(want) {
		t.Fatalf("want %d servers, got %d", len(want), len(servers))
	}
	for i, s := range servers {
		w := want[i]
		if s.Name != w.name || pulumitest.Str(s.Inputs, "serverType") != w.typ {
			t.Errorf("server %d: %s %s, want %s %s", i, s.Name, pulumitest.Str(s.Inputs, "serverType"), w.name, w.typ)
		}
		if pulumitest.Str(s.Inputs, "image") != "alma-10" || pulumitest.Str(s.Inputs, "location") != "fsn1" {
			t.Errorf("server %s: %v", s.Name, s.Inputs)
		}
		if !s.Inputs["deleteProtection"].BoolValue() || !s.Inputs["rebuildProtection"].BoolValue() {
			t.Errorf("server %s lacks delete/rebuild protection", s.Name)
		}
		ignored := append([]string(nil), s.IgnoreChanges...)
		sort.Strings(ignored)
		if !reflect.DeepEqual(ignored, []string{"image", "sshKeys", "userData"}) {
			t.Errorf("server %s ignores %v", s.Name, s.IgnoreChanges)
		}
		if pulumitest.Str(s.Inputs["labels"].ObjectValue(), "role") != w.role {
			t.Errorf("server %s labels %v", s.Name, s.Inputs["labels"])
		}
		ip := s.Inputs["networks"].ArrayValue()[0].ObjectValue()
		if pulumitest.Str(ip, "ip") != w.ip {
			t.Errorf("server %s private IP %v", s.Name, ip)
		}
		if !s.Inputs["userData"].ContainsSecrets() {
			t.Errorf("server %s user data (with its host key) is plaintext in state", s.Name)
		}
		ud := pulumitest.Unwrap(s.Inputs["userData"]).StringValue()
		for _, want := range []string{
			"PasswordAuthentication no", "ssh_deletekeys: true", "ssh_genkeytypes: []",
			"  ed25519_private: |\n    -----BEGIN OPENSSH PRIVATE KEY-----\n    AAAA\n    BBBB\n    -----END OPENSSH PRIVATE KEY-----\n",
			"  ed25519_public: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKey\n",
		} {
			if !strings.Contains(ud, want) {
				t.Errorf("server %s user data lacks %q:\n%s", s.Name, want, ud)
			}
		}
	}
}

// The account's vCPU cap has no room for a replacement next to the old
// server, and a primary IP belongs to one server at a time.
func TestServersReplaceDeleteFirst(t *testing.T) {
	m := mustRun(t, baseConfig())
	for _, s := range m.ByType(serverType) {
		if !s.DeleteBeforeReplace {
			t.Errorf("server %s would be replaced create-first", s.Name)
		}
	}
}

func TestVolumes(t *testing.T) {
	m := mustRun(t, with(map[string]string{"watchtower:nodeVolumeGb": "40", "watchtower:proxyVolumeGb": "12"}))
	volumes := m.ByType(volumeType)
	if len(volumes) != 4 {
		t.Fatalf("want 4 volumes, got %d", len(volumes))
	}
	for _, v := range volumes {
		want := 40.0
		if v.Name == names.ProxyName+"-data" {
			want = 12
		}
		if v.Inputs["size"].NumberValue() != want || pulumitest.Str(v.Inputs, "location") != "fsn1" {
			t.Errorf("volume %s: %v", v.Name, v.Inputs)
		}
		// Unformatted (LUKS goes on it) and never mounted by Hetzner.
		if v.Inputs["automount"].BoolValue() || pulumitest.Str(v.Inputs, "format") != "" {
			t.Errorf("volume %s is formatted or automounted", v.Name)
		}
		if !v.Protect {
			t.Errorf("volume %s is not protected", v.Name)
		}
	}
	if got := len(m.ByType(attachmentType)); got != 4 {
		t.Errorf("want 4 volume attachments, got %d", got)
	}
}

// The Kubernetes design's Floating IP is gone: the proxy's primary IPv4 is
// the VPN address.
func TestNoFloatingIP(t *testing.T) {
	m := mustRun(t, baseConfig())
	if got := m.ByType(fipType); len(got) != 0 {
		t.Errorf("floating IPs %v", got)
	}
}

func policyOf(t *testing.T, m *pulumitest.Mocks, bucket string) policyDoc {
	t.Helper()
	r := m.Named(t, bucket+"-policy")
	raw := pulumitest.Unwrap(r.Inputs["policy"])
	var doc policyDoc
	if err := json.Unmarshal([]byte(raw.StringValue()), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestBuckets(t *testing.T) {
	m := mustRun(t, baseConfig())
	buckets := m.ByType(bucketType)
	if len(buckets) != len(names.Buckets) {
		t.Fatalf("want %d buckets, got %d", len(names.Buckets), len(buckets))
	}
	for _, b := range buckets {
		if !b.Protect {
			t.Errorf("bucket %s is not protected", b.Name)
		}
		if pulumitest.Str(b.Inputs, "acl") != "private" {
			t.Errorf("bucket %s acl %v", b.Name, b.Inputs["acl"])
		}
	}
	for _, p := range m.ByType(policyType) {
		if !p.Inputs["policy"].ContainsSecrets() {
			t.Errorf("policy %s names access keys in plaintext", p.Name)
		}
	}
}

// Every bucket keeps out every key but the admin key and the cluster key,
// and the admin key is never locked out (Pulumi itself uses it).
func TestBucketPolicies(t *testing.T) {
	m := mustRun(t, baseConfig())
	admin := principal(1234, "ADMINKEY")
	cluster := principal(1234, "CLUSTERKEY")
	for _, b := range names.Buckets {
		name := names.BucketName("test-wt", b.Suffix)
		doc := policyOf(t, m, name)
		first := doc.Statement[0]
		if first.Effect != "Deny" || first.Action != "s3:*" || first.NotPrincipal == nil ||
			!reflect.DeepEqual(first.NotPrincipal.AWS, []string{admin, cluster}) {
			t.Errorf("%s: first statement %+v", name, first)
		}
		want := []string{"arn:aws:s3:::" + name, "arn:aws:s3:::" + name + "/*"}
		if !reflect.DeepEqual(first.Resource, want) {
			t.Errorf("%s: resources %v", name, first.Resource)
		}
		statements := 1
		if b.WriteOnly {
			statements++
		}
		if b.Suffix == names.BucketLogArchive {
			statements++
		}
		if len(doc.Statement) != statements {
			t.Errorf("%s: write-only %v but %d statements", name, b.WriteOnly, len(doc.Statement))
		}
	}
}

// The cluster key can write to the log archive and the Postgres backups and
// nothing else: a host compromise cannot read back, list or erase either.
// Policy actions arrive from JSON as []interface{}.
func TestWriteOnlyForTheCluster(t *testing.T) {
	m := mustRun(t, baseConfig())
	for _, bucket := range []string{"test-wt-logs-archive", "test-wt-postgres-backups"} {
		deny := policyOf(t, m, bucket).Statement[1]
		if deny.Effect != "Deny" || deny.Principal == nil || deny.Principal.AWS[0] != principal(1234, "CLUSTERKEY") {
			t.Fatalf("%s: write-only statement %+v", bucket, deny)
		}
		denied := map[string]bool{}
		for _, a := range deny.Action.([]interface{}) {
			denied[a.(string)] = true
		}
		for _, must := range []string{"s3:GetObject*", "s3:DeleteObject", "s3:ListBucket", "s3:PutBucketPolicy", "s3:PutLifecycleConfiguration", "s3:DeleteBucket"} {
			if !denied[must] {
				t.Errorf("%s: write-only key may still %s", bucket, must)
			}
		}
		if denied["s3:PutObject"] {
			t.Errorf("%s: write-only key cannot write", bucket)
		}
		// Hetzner answers 503 to the whole policy over this one.
		if denied["s3:GetObjectAttributes"] {
			t.Errorf("%s: names s3:GetObjectAttributes, which Hetzner rejects", bucket)
		}
	}
	gdpr := policyOf(t, m, "test-wt-logs-archive").Statement[2]
	if gdpr.Action != "s3:PutObject" || gdpr.Resource[0] != "arn:aws:s3:::test-wt-logs-archive/gdpr-audit/*" ||
		gdpr.Principal.AWS[0] != principal(1234, "CLUSTERKEY") {
		t.Errorf("gdpr-audit statement %+v", gdpr)
	}
}

func TestLifecycle(t *testing.T) {
	m := mustRun(t, baseConfig())
	got := map[string]string{}
	for _, p := range m.ByType(ilmType) {
		var parts []string
		for _, r := range p.Inputs["rules"].ArrayValue() {
			rule := r.ObjectValue()
			// No status: the provider sets it and refuses one given.
			if _, set := rule["status"]; set {
				t.Errorf("%s sets a rule status", p.Name)
			}
			parts = append(parts, pulumitest.Str(rule, "filter")+pulumitest.Str(rule, "expiration"))
		}
		got[p.Name] = strings.Join(parts, " ")
	}
	want := map[string]string{
		"test-wt-loki-lifecycle":         "60d",
		"test-wt-mimir-blocks-lifecycle": "180d",
		"test-wt-tempo-lifecycle":        "60d",
		// gdpr-audit/ is deliberately absent: erasure records are kept.
		"test-wt-logs-archive-lifecycle": "containers/90d journal/90d audit/90d",
		// The backups' retention is this rule alone.
		"test-wt-postgres-backups-lifecycle": "90d",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lifecycle %v, want %v", got, want)
	}
}

func TestDNSRecords(t *testing.T) {
	m := mustRun(t, baseConfig())
	got := map[string][]string{}
	for _, r := range m.ByType(recordType) {
		if pulumitest.Str(r.Inputs, "type") != "A" || r.Inputs["ttl"].NumberValue() != 300 ||
			pulumitest.Str(r.Inputs, "managedZone") != "watchtower" {
			t.Errorf("record %s: %v", r.Name, r.Inputs)
		}
		var vals []string
		for _, v := range r.Inputs["rrdatas"].ArrayValue() {
			vals = append(vals, v.StringValue())
		}
		got[pulumitest.Str(r.Inputs, "name")] = vals
	}
	want := map[string][]string{
		// The private endpoint resolves only to the in-tunnel address.
		names.Domain + ".": {names.TunnelIP},
		// Peers connect to the proxy, never to a data node.
		names.VPNHost + ".": {proxyAddress},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("records %v, want %v", got, want)
	}
}

func TestZoneMustServeTheDomain(t *testing.T) {
	m := newMocks("other.example.")()
	err := pulumitest.Run(t, opts(baseConfig()), program, m)
	if err == nil || !strings.Contains(err.Error(), "not "+names.Domain) {
		t.Errorf("err = %v", err)
	}
}

func TestBucketPolicyEncodeFailure(t *testing.T) {
	marshalJSON = func(interface{}) ([]byte, error) { return nil, errors.New("encode failed") }
	t.Cleanup(func() { marshalJSON = json.Marshal })
	if _, err := runWith(t, baseConfig(), program); err == nil || !strings.Contains(err.Error(), "encode failed") {
		t.Errorf("err = %v", err)
	}
}

// withHosts runs config, providers, network and hosts under mocks and hands
// the hosts to fn, whose output it waits for.
func withHosts(t *testing.T, cfg map[string]string, fn func(*Config, *hosts) pulumi.StringOutput) string {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	var got string
	_, err := runWith(t, cfg, func(ctx *pulumi.Context) error {
		c, err := loadConfig(ctx)
		if err != nil {
			return err
		}
		p, err := newProviders(ctx, c)
		if err != nil {
			return err
		}
		net, err := newNetwork(ctx, c, p)
		if err != nil {
			return err
		}
		hs, err := newHosts(ctx, c, p, net)
		if err != nil {
			return err
		}
		fn(c, hs).ApplyT(func(s string) string {
			got = s
			wg.Done()
			return s
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	return got
}

func inventory(t *testing.T, cfg map[string]string) map[string]interface{} {
	t.Helper()
	rendered := withHosts(t, cfg, inventoryJSON)
	var inv map[string]interface{}
	if err := json.Unmarshal([]byte(rendered), &inv); err != nil {
		t.Fatal(err)
	}
	return inv
}

func group(inv map[string]interface{}, name string) map[string]interface{} {
	all := inv["all"].(map[string]interface{})
	g := all["children"].(map[string]interface{})[name].(map[string]interface{})
	return g["hosts"].(map[string]interface{})
}

func TestInventoryGroups(t *testing.T) {
	inv := inventory(t, with(map[string]string{"watchtower:nodeCount": "4"}))
	if got := keysOf(group(inv, "proxy")); !reflect.DeepEqual(got, []string{names.ProxyName}) {
		t.Errorf("proxy = %v", got)
	}
	nodes := group(inv, "nodes")
	if got := keysOf(nodes); !reflect.DeepEqual(got, []string{"watchtower-1", "watchtower-2", "watchtower-3", "watchtower-4"}) {
		t.Errorf("nodes = %v", got)
	}
	n := nodes["watchtower-2"].(map[string]interface{})
	if n["public_ip"] != nodeAddress || n["private_ip"] != names.PrivateIP(2) || n["mesh_ip"] != names.MeshIP(2) ||
		n["node_index"] != 2.0 || n["zone"] != "b" {
		t.Errorf("node vars %v", n)
	}
	// Mock IDs are numbers; the volume's must arrive as one.
	if _, ok := n["volume_id"].(float64); !ok {
		t.Errorf("volume_id %v", n["volume_id"])
	}
	p := group(inv, "proxy")[names.ProxyName].(map[string]interface{})
	if p["public_ip"] != proxyAddress || p["mesh_ip"] != names.MeshIP(0) || p["private_ip"] != names.PrivateIP(0) {
		t.Errorf("proxy vars %v", p)
	}
	if _, ok := p["zone"]; ok {
		t.Errorf("the proxy has a Tempo zone: %v", p)
	}
}

// Ansible gets every shared name from here, never spelling one itself.
func TestInventoryVars(t *testing.T) {
	cfg := with(map[string]string{
		"watchtower:ciCidrs":             `["203.0.113.9/32","2001:db8::9/128"]`,
		"watchtower:breakGlassCidrs":     `["198.51.100.99/32"]`,
		"watchtower:wireguardAllowCidrs": `["192.0.2.0/24"]`,
	})
	inv := inventory(t, cfg)
	vars := inv["all"].(map[string]interface{})["vars"].(map[string]interface{})
	for key, want := range map[string]interface{}{
		"watchtower_ci_cidrs":          []interface{}{"203.0.113.9/32", "2001:db8::9/128"},
		"watchtower_break_glass_cidrs": []interface{}{"198.51.100.99/32"},
		"watchtower_bastion": map[string]interface{}{
			"name": names.BastionName, "zone": names.BastionZone,
			"project": names.GCPProject, "host_key": cfg["watchtower:bastionHostKey"],
		},
		"watchtower_wireguard_cidrs": []interface{}{"192.0.2.0/24"},
		"watchtower_wireguard_port":  float64(names.PortWireGuard),
		"watchtower_private_cidr":    names.SubnetCIDR,
		"watchtower_mesh_cidr":       names.MeshCIDR,
		"watchtower_mesh_port":       float64(names.MeshPort),
		"watchtower_domain":          names.Domain,
		"watchtower_vpn_host":        names.VPNHost,
		"watchtower_tunnel_ip":       names.TunnelIP,
		"watchtower_tunnel_cidr":     names.TunnelCIDR,
		"watchtower_gcp_project":     names.GCPProject,
		"watchtower_s3_endpoint":     names.S3Endpoint,
		"watchtower_s3_region":       names.S3Region,
		"watchtower_archive_prefixes": map[string]interface{}{
			"containers": "containers/", "journal": "journal/", "audit": "audit/",
		},
		"watchtower_postgres_backup_prefix": "grafana/",
		"watchtower_retention_days": map[string]interface{}{
			"loki": 30.0, "mimir": 90.0, "tempo": 30.0, "log_archive": 90.0, "postgres_backup": 90.0,
		},
	} {
		if !reflect.DeepEqual(vars[key], want) {
			t.Errorf("%s = %v, want %v", key, vars[key], want)
		}
	}
	buckets := vars["watchtower_buckets"].(map[string]interface{})
	for _, b := range names.Buckets {
		if buckets[b.Suffix] != "test-wt-"+b.Suffix {
			t.Errorf("bucket %s = %v", b.Suffix, buckets[b.Suffix])
		}
	}
}

func TestInventoryEncodeFailure(t *testing.T) {
	marshalJSON = func(interface{}) ([]byte, error) { return nil, errors.New("encode failed") }
	t.Cleanup(func() { marshalJSON = json.Marshal })
	_, err := runWith(t, baseConfig(), func(ctx *pulumi.Context) error {
		c, _ := loadConfig(ctx)
		p, _ := newProviders(ctx, c)
		net, _ := newNetwork(ctx, c, p)
		hs, _ := newHosts(ctx, c, p, net)
		ctx.Export("inventory", inventoryJSON(c, hs))
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "encode failed") {
		t.Errorf("err = %v", err)
	}
}

func TestKnownHosts(t *testing.T) {
	got := withHosts(t, baseConfig(), func(_ *Config, hs *hosts) pulumi.StringOutput { return knownHosts(hs.all()) })
	key := " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKey\n"
	// The proxy under the tunnel address too: a VPN peer's way in.
	want := proxyAddress + "," + names.PrivateIP(0) + "," + names.TunnelIP + "," + names.ProxyName + key
	for i := 1; i <= 3; i++ {
		want += nodeAddress + "," + names.PrivateIP(i) + "," + names.NodeName(i) + key
	}
	if got != want {
		t.Errorf("knownHosts =\n%s\nwant\n%s", got, want)
	}
}

func TestConfigValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg  map[string]string
		want string
	}{
		"too few nodes":         {with(map[string]string{"watchtower:nodeCount": "2"}), "at least 3 nodes"},
		"too many nodes":        {with(map[string]string{"watchtower:nodeCount": "10"}), "at most 9 nodes"},
		"small node volume":     {with(map[string]string{"watchtower:nodeVolumeGb": "9"}), "nodeVolumeGb 9"},
		"huge proxy volume":     {with(map[string]string{"watchtower:proxyVolumeGb": "10241"}), "proxyVolumeGb 10241"},
		"rsa key":               {with(map[string]string{"watchtower:sshPublicKey": "ssh-rsa AAAA"}), "ed25519"},
		"no ci cidrs":           {with(map[string]string{"watchtower:ciCidrs": "[]"}), "ciCidrs must not be empty"},
		"no break-glass cidrs":  {with(map[string]string{"watchtower:breakGlassCidrs": "[]"}), "breakGlassCidrs must not be empty"},
		"missing break glass":   {with(map[string]string{"watchtower:breakGlassCidrs": ""}), "watchtower:breakGlassCidrs"},
		"open break-glass cidr": {with(map[string]string{"watchtower:breakGlassCidrs": `["::/0"]`}), "breakGlassCidrs must not contain"},
		"bad bastion host key":  {with(map[string]string{"watchtower:bastionHostKey": "ssh-rsa AAAA"}), "bastionHostKey must be"},
		"missing bastion key":   {with(map[string]string{"watchtower:bastionHostKey": ""}), "watchtower:bastionHostKey"},
		"missing ci cidrs":      {with(map[string]string{"watchtower:ciCidrs": ""}), "watchtower:ciCidrs"},
		"no wireguard cidrs":    {with(map[string]string{"watchtower:wireguardAllowCidrs": "[]"}), "wireguardAllowCidrs must not be empty"},
		"bad cidr":              {with(map[string]string{"watchtower:ciCidrs": `["300.1.1.1/8"]`}), "invalid CIDR"},
		"open ci cidr":          {with(map[string]string{"watchtower:ciCidrs": `["0.0.0.0/0"]`}), "ciCidrs must not contain"},
		"bad bucket prefix":     {with(map[string]string{"watchtower:bucketPrefix": "Bad_Prefix"}), "bucketPrefix"},
		"zero project":          {with(map[string]string{"watchtower:hetznerProjectId": "0"}), "numeric project ID"},
		"placeholder project":   {with(map[string]string{"watchtower:hetznerProjectId": "REPLACE"}), "hetznerProjectId"},
		"missing ssh key":       {with(map[string]string{"watchtower:sshPublicKey": ""}), "watchtower:sshPublicKey"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runWith(t, tc.cfg, program)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// The bucket policies' key IDs come from Secret Manager in the stack's GCP
// project, through the explicit provider.
func TestSecretsComeFromSecretManager(t *testing.T) {
	m := mustRun(t, baseConfig())
	var got []string
	for _, inv := range m.Invokes() {
		if inv.Token != secretToken {
			continue
		}
		got = append(got, pulumitest.Str(inv.Args, "secret"))
		if pulumitest.Str(inv.Args, "project") != names.GCPProject || !strings.Contains(inv.Provider, "pulumi:providers:gcp::gcp") {
			t.Errorf("secret lookup %+v", inv)
		}
	}
	sort.Strings(got)
	want := []string{"s3-admin-access-key", "s3-cluster-access-key"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("secrets read %v, want %v", got, want)
	}
}

func TestEmptySecretFails(t *testing.T) {
	m := goodZone()
	m.Calls[secretToken] = func(args resource.PropertyMap) (resource.PropertyMap, error) {
		v := secretValue(pulumitest.Str(args, "secret"))
		if pulumitest.Str(args, "secret") == "s3-cluster-access-key" {
			v = ""
		}
		return resource.PropertyMap{"secretData": resource.NewStringProperty(v)}, nil
	}
	err := pulumitest.Run(t, opts(baseConfig()), program, m)
	if err == nil || !strings.Contains(err.Error(), "secret s3-cluster-access-key in watchtower-observe is empty") {
		t.Errorf("err = %v", err)
	}
}

// The committed stack file must at least parse as config this program reads,
// and hold nothing secret: the repo is mirrored publicly.
func TestStackFileKeys(t *testing.T) {
	b, err := os.ReadFile("Pulumi.prod.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "secure:") {
		t.Error("Pulumi.prod.yaml holds a secret; store it in Secret Manager (scripts/secret.sh put)")
	}
	for _, key := range []string{
		"bucketPrefix", "hetznerProjectId: \"16527471\"", "sshPublicKey", "ciCidrs", "breakGlassCidrs", "bastionHostKey",
		"location: fsn1", "nodeServerType: cax31", "proxyServerType: cax11", "nodeCount: \"3\"", "deleteProtection: \"true\"",
	} {
		if !strings.Contains(s, "watchtower:"+key) {
			t.Errorf("Pulumi.prod.yaml lacks watchtower:%s", key)
		}
	}
	for _, gone := range []string{"watchtower:serverType"} {
		if strings.Contains(s, gone) {
			t.Errorf("Pulumi.prod.yaml still sets %s, which nothing reads", gone)
		}
	}
}
