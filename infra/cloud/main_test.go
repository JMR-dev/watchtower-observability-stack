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
	serverType   = "hcloud:index/server:Server"
	firewallType = "hcloud:index/firewall:Firewall"
	fipType      = "hcloud:index/floatingIp:FloatingIp"
	hostKeyType  = "tls:index/privateKey:PrivateKey"
	hostPrivate  = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----\n"
	hostPublic   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKey\n"
	bucketType   = "minio:index/s3Bucket:S3Bucket"
	policyType   = "minio:index/s3BucketPolicy:S3BucketPolicy"
	ilmType      = "minio:index/ilmPolicy:IlmPolicy"
	recordType   = "gcp:dns/recordSet:RecordSet"
	zoneToken    = "gcp:dns/getManagedZone:getManagedZone"
	secretToken  = "gcp:secretmanager/getSecretVersion:getSecretVersion"
	fipAddress   = "198.51.100.7"
	nodeAddress  = "203.0.113.10"
)

func baseConfig() map[string]string {
	return map[string]string{
		"watchtower:sshPublicKey":     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest test@example",
		"watchtower:bucketPrefix":     "test-wt",
		"watchtower:hetznerProjectId": "1234",
		"watchtower:adminCidrs":       `["198.51.100.0/24"]`,
		"watchtower:ciCidrs":          `["34.26.149.196/32"]`,
	}
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

// secretValue is what the mocked Secret Manager holds: s3-loki-access-key is
// "LOKIKEY", and so on.
func secretValue(id string) string {
	key := strings.TrimSuffix(strings.TrimPrefix(id, "s3-"), "-access-key")
	return strings.ToUpper(key) + "KEY"
}

// newMocks hands out numeric IDs (Hetzner references resources by integer)
// and answers the zone and secret lookups.
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
				fipType:    {"ipAddress": resource.NewStringProperty(fipAddress)},
				hostKeyType: {
					"privateKeyOpenssh": resource.NewStringProperty(hostPrivate),
					"publicKeyOpenssh":  resource.NewStringProperty(hostPublic),
				},
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

func sources(r pulumitest.Resource, port string) []string {
	for _, v := range r.Inputs["rules"].ArrayValue() {
		rule := v.ObjectValue()
		if pulumitest.Str(rule, "port") != port {
			continue
		}
		var out []string
		for _, s := range rule["sourceIps"].ArrayValue() {
			out = append(out, s.StringValue())
		}
		return out
	}
	return nil
}

func TestFirewall(t *testing.T) {
	m := mustRun(t, baseConfig())
	fws := m.ByType(firewallType)
	if len(fws) != 1 {
		t.Fatalf("want one firewall, got %d", len(fws))
	}
	fw := fws[0]
	ops := []string{"198.51.100.0/24", "34.26.149.196/32"}
	for _, port := range []string{"22", "6443"} {
		if got := sources(fw, port); !reflect.DeepEqual(got, ops) {
			t.Errorf("port %s open to %v, want %v", port, got, ops)
		}
	}
	if got := sources(fw, "51820"); !reflect.DeepEqual(got, []string{"0.0.0.0/0", "::/0"}) {
		t.Errorf("WireGuard open to %v", got)
	}
	applies := fw.Inputs["applyTos"].ArrayValue()
	if len(applies) != 1 || pulumitest.Str(applies[0].ObjectValue(), "labelSelector") != "role="+names.NodeLabelRole {
		t.Errorf("firewall applies to %v", applies)
	}
}

func TestServers(t *testing.T) {
	m := mustRun(t, with(map[string]string{"watchtower:nodeCount": "4", "watchtower:deleteProtection": "true"}))
	servers := m.ByType(serverType)
	if len(servers) != 4 {
		t.Fatalf("want 4 servers, got %d", len(servers))
	}
	// Registration is asynchronous, so the mocks see servers in any order.
	sort.Slice(servers, func(a, b int) bool { return servers[a].Name < servers[b].Name })
	for i, s := range servers {
		if s.Name != names.NodeName(i+1) {
			t.Errorf("server %d named %s", i, s.Name)
		}
		if pulumitest.Str(s.Inputs, "image") != "alma-10" || pulumitest.Str(s.Inputs, "location") != "nbg1" {
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
		labels := s.Inputs["labels"].ObjectValue()
		if pulumitest.Str(labels, "role") != names.NodeLabelRole {
			t.Errorf("server %s labels %v", s.Name, labels)
		}
		ip := s.Inputs["networks"].ArrayValue()[0].ObjectValue()
		if pulumitest.Str(ip, "ip") != names.PrivateIP(i+1) {
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

func TestFloatingIP(t *testing.T) {
	m := mustRun(t, baseConfig())
	fips := m.ByType(fipType)
	if len(fips) != 1 {
		t.Fatalf("want one floating IP, got %d", len(fips))
	}
	f := fips[0]
	if !f.Protect {
		t.Error("floating IP is not protected")
	}
	if !reflect.DeepEqual(f.IgnoreChanges, []string{"serverId"}) {
		t.Errorf("floating IP ignores %v; Pulumi would fight fipd", f.IgnoreChanges)
	}
	if pulumitest.Str(f.Inputs["labels"].ObjectValue(), "role") != names.FloatingIPLabel {
		t.Errorf("floating IP labels %v; fipd finds it by label", f.Inputs["labels"])
	}
	if pulumitest.Str(f.Inputs, "type") != "ipv4" {
		t.Errorf("floating IP type %v", f.Inputs["type"])
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

// Every bucket keeps out every key but the admin key and its own, and the
// admin key is never locked out (Pulumi itself uses it).
func TestBucketPolicies(t *testing.T) {
	m := mustRun(t, baseConfig())
	admin := principal(1234, "ADMINKEY")
	for _, b := range names.Buckets {
		name := names.BucketName("test-wt", b.Suffix)
		doc := policyOf(t, m, name)
		first := doc.Statement[0]
		owner := principal(1234, strings.ToUpper(b.Key)+"KEY")
		if first.Effect != "Deny" || first.Action != "s3:*" || first.NotPrincipal == nil ||
			!reflect.DeepEqual(first.NotPrincipal.AWS, []string{admin, owner}) {
			t.Errorf("%s: first statement %+v", name, first)
		}
		want := []string{"arn:aws:s3:::" + name, "arn:aws:s3:::" + name + "/*"}
		if !reflect.DeepEqual(first.Resource, want) {
			t.Errorf("%s: resources %v", name, first.Resource)
		}
		if b.WriteOnly != (len(doc.Statement) == 3) {
			t.Errorf("%s: write-only %v but %d statements", name, b.WriteOnly, len(doc.Statement))
		}
	}
}

// The log-archive key can write and nothing else: a node compromise cannot
// read back, list or erase the archive. Policy actions arrive from JSON as
// []interface{}.
func TestLogArchiveKeyIsWriteOnly(t *testing.T) {
	m := mustRun(t, baseConfig())
	doc := policyOf(t, m, "test-wt-logs-archive")
	deny := doc.Statement[1]
	if deny.Effect != "Deny" || deny.Principal == nil || deny.Principal.AWS[0] != principal(1234, "LOGSHIPKEY") {
		t.Fatalf("write-only statement %+v", deny)
	}
	denied := map[string]bool{}
	for _, a := range deny.Action.([]interface{}) {
		denied[a.(string)] = true
	}
	for _, must := range []string{"s3:GetObject", "s3:DeleteObject", "s3:ListBucket", "s3:PutBucketPolicy", "s3:PutLifecycleConfiguration", "s3:DeleteBucket"} {
		if !denied[must] {
			t.Errorf("write-only key may still %s", must)
		}
	}
	if denied["s3:PutObject"] {
		t.Error("write-only key cannot write")
	}
	gdpr := doc.Statement[2]
	if gdpr.Action != "s3:PutObject" || gdpr.Resource[0] != "arn:aws:s3:::test-wt-logs-archive/gdpr-audit/*" ||
		gdpr.Principal.AWS[0] != principal(1234, "LOGSHIPKEY") {
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
			parts = append(parts, pulumitest.Str(rule, "filter")+pulumitest.Str(rule, "expiration")+"/"+pulumitest.Str(rule, "status"))
		}
		got[p.Name] = strings.Join(parts, " ")
	}
	want := map[string]string{
		"test-wt-loki-lifecycle":         "60d/Enabled",
		"test-wt-mimir-blocks-lifecycle": "180d/Enabled",
		"test-wt-tempo-lifecycle":        "60d/Enabled",
		// gdpr-audit/ is deliberately absent: erasure records are kept.
		"test-wt-logs-archive-lifecycle": "containers/90d/Enabled journal/90d/Enabled audit/90d/Enabled",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lifecycle %v, want %v", got, want)
	}
}

func TestDNSRecords(t *testing.T) {
	m := mustRun(t, with(map[string]string{"watchtower:nodeCount": "4"}))
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
		names.Domain + ".":  {names.TunnelIP},
		names.VPNHost + ".": {fipAddress},
		// Control-plane nodes only: the fourth node is a worker.
		names.APIHost + ".": {nodeAddress, nodeAddress, nodeAddress},
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

// inventory runs the node, Floating IP and inventory code under mocks and
// returns the rendered inventory.
func inventory(t *testing.T, cfg map[string]string) map[string]interface{} {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	var rendered string
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
		nodes, err := newNodes(ctx, c, p, net)
		if err != nil {
			return err
		}
		fip, err := newFloatingIP(ctx, c, p, nodes[0])
		if err != nil {
			return err
		}
		inventoryJSON(c, nodes, fip).ApplyT(func(s string) string {
			rendered = s
			wg.Done()
			return s
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	var inv map[string]interface{}
	if err := json.Unmarshal([]byte(rendered), &inv); err != nil {
		t.Fatal(err)
	}
	return inv
}

func hostsOf(inv map[string]interface{}, group string) []string {
	all := inv["all"].(map[string]interface{})
	g := all["children"].(map[string]interface{})[group].(map[string]interface{})
	var out []string
	for h := range g["hosts"].(map[string]interface{}) {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Kubespray: nodes 1-3 run etcd and the control plane, later nodes are
// workers only, and every node runs workloads.
func TestInventoryGroups(t *testing.T) {
	inv := inventory(t, with(map[string]string{"watchtower:nodeCount": "4"}))
	cp := []string{"watchtower-1", "watchtower-2", "watchtower-3"}
	for group, want := range map[string][]string{
		"kube_control_plane": cp,
		"etcd":               cp,
		"kube_node":          {"watchtower-1", "watchtower-2", "watchtower-3", "watchtower-4"},
	} {
		if got := hostsOf(inv, group); !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", group, got, want)
		}
	}
	all := inv["all"].(map[string]interface{})
	if all["vars"].(map[string]interface{})["watchtower_floating_ipv4"] != fipAddress {
		t.Errorf("vars %v", all["vars"])
	}
	h := all["hosts"].(map[string]interface{})["watchtower-2"].(map[string]interface{})
	if h["ip"] != names.PrivateIP(2) || h["access_ip"] != names.PrivateIP(2) || h["ansible_host"] != nodeAddress {
		t.Errorf("host vars %v", h)
	}
}

// The node firewall (roles/firewall) gets the Hetzner firewall's address
// lists: admin and CI together for SSH and the API, WireGuard's own, and the
// private network the other nodes talk over.
func TestInventoryFirewallVars(t *testing.T) {
	inv := inventory(t, with(map[string]string{
		"watchtower:adminCidrs":          `["198.51.100.0/24","2001:db8::/32"]`,
		"watchtower:ciCidrs":             `["203.0.113.9/32"]`,
		"watchtower:wireguardAllowCidrs": `["192.0.2.0/24"]`,
	}))
	vars := inv["all"].(map[string]interface{})["vars"].(map[string]interface{})
	for key, want := range map[string]interface{}{
		"watchtower_admin_cidrs":     []interface{}{"198.51.100.0/24", "2001:db8::/32", "203.0.113.9/32"},
		"watchtower_wireguard_cidrs": []interface{}{"192.0.2.0/24"},
		"watchtower_wireguard_port":  float64(names.PortWireGuard),
		"watchtower_private_cidr":    names.NetworkCIDR,
	} {
		if !reflect.DeepEqual(vars[key], want) {
			t.Errorf("%s = %v, want %v", key, vars[key], want)
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
		nodes, _ := newNodes(ctx, c, p, net)
		fip, _ := newFloatingIP(ctx, c, p, nodes[0])
		ctx.Export("inventory", inventoryJSON(c, nodes, fip))
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "encode failed") {
		t.Errorf("err = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg  map[string]string
		want string
	}{
		"too few nodes":       {with(map[string]string{"watchtower:nodeCount": "2"}), "need 3 nodes"},
		"too many nodes":      {with(map[string]string{"watchtower:nodeCount": "11"}), "at most 10"},
		"rsa key":             {with(map[string]string{"watchtower:sshPublicKey": "ssh-rsa AAAA"}), "ed25519"},
		"no admin cidrs":      {with(map[string]string{"watchtower:adminCidrs": "[]"}), "adminCidrs must not be empty"},
		"missing admin cidrs": {with(map[string]string{"watchtower:adminCidrs": ""}), "watchtower:adminCidrs"},
		"no wireguard cidrs":  {with(map[string]string{"watchtower:wireguardAllowCidrs": "[]"}), "wireguardAllowCidrs must not be empty"},
		"bad cidr":            {with(map[string]string{"watchtower:adminCidrs": `["300.1.1.1/8"]`}), "invalid CIDR"},
		"open ci cidr":        {with(map[string]string{"watchtower:ciCidrs": `["0.0.0.0/0"]`}), "ciCidrs must not contain"},
		"bad bucket prefix":   {with(map[string]string{"watchtower:bucketPrefix": "Bad_Prefix"}), "bucketPrefix"},
		"zero project":        {with(map[string]string{"watchtower:hetznerProjectId": "0"}), "numeric project ID"},
		"placeholder project": {with(map[string]string{"watchtower:hetznerProjectId": "REPLACE"}), "hetznerProjectId"},
		"missing ssh key":     {with(map[string]string{"watchtower:sshPublicKey": ""}), "watchtower:sshPublicKey"},
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
	want := []string{"s3-admin-access-key", "s3-logship-access-key", "s3-loki-access-key", "s3-mimir-access-key", "s3-tempo-access-key"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("secrets read %v, want %v", got, want)
	}
}

func TestEmptySecretFails(t *testing.T) {
	m := goodZone()
	m.Calls[secretToken] = func(args resource.PropertyMap) (resource.PropertyMap, error) {
		v := secretValue(pulumitest.Str(args, "secret"))
		if pulumitest.Str(args, "secret") == "s3-tempo-access-key" {
			v = ""
		}
		return resource.PropertyMap{"secretData": resource.NewStringProperty(v)}, nil
	}
	err := pulumitest.Run(t, opts(baseConfig()), program, m)
	if err == nil || !strings.Contains(err.Error(), "secret s3-tempo-access-key in watchtower-observe is empty") {
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
	if strings.Contains(string(b), "secure:") {
		t.Error("Pulumi.prod.yaml holds a secret; store it in Secret Manager (scripts/secret.sh put)")
	}
	for _, key := range []string{"bucketPrefix", "hetznerProjectId", "sshPublicKey", "adminCidrs", "ciCidrs", "deleteProtection: \"true\""} {
		if !strings.Contains(string(b), "watchtower:"+key) {
			t.Errorf("Pulumi.prod.yaml lacks watchtower:%s", key)
		}
	}
}

func TestKnownHosts(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	var got string
	_, err := runWith(t, with(map[string]string{"watchtower:nodeCount": "3"}), func(ctx *pulumi.Context) error {
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
		nodes, err := newNodes(ctx, c, p, net)
		if err != nil {
			return err
		}
		knownHosts(nodes).ApplyT(func(s string) string {
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
	want := ""
	for i := 1; i <= 3; i++ {
		want += nodeAddress + "," + names.NodeName(i) + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKey\n"
	}
	if got != want {
		t.Errorf("knownHosts =\n%s\nwant\n%s", got, want)
	}
}
