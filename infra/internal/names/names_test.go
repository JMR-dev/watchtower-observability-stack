package names

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestNamesAreStable(t *testing.T) {
	for got, want := range map[string]string{
		BucketName("p", "loki"): "p-loki",
		NodeName(2):             "watchtower-2",
		PrivateIP(0):            "10.20.1.10",
		PrivateIP(3):            "10.20.1.13",
		MeshIP(0):               "10.30.0.10",
		MeshIP(2):               "10.30.0.12",
		VPNHost:                 "vpn.watchtower.jasonmross.dev",
		ProxyName:               "watchtower-proxy",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

// The admin and agent halves split the tunnel range exactly, and the proxy's
// own address is admin: verify.sh pushes from it with any tenant.
func TestTunnelHalves(t *testing.T) {
	tunnel := netip.MustParsePrefix(TunnelCIDR)
	admin := netip.MustParsePrefix(AdminCIDR)
	agent := netip.MustParsePrefix(AgentCIDR)
	if admin.Bits() != tunnel.Bits()+1 || agent.Bits() != tunnel.Bits()+1 {
		t.Errorf("halves %s and %s of %s", admin, agent, tunnel)
	}
	if admin.Addr() != tunnel.Addr() || !tunnel.Contains(agent.Addr()) || admin.Overlaps(agent) {
		t.Errorf("%s and %s do not split %s", admin, agent, tunnel)
	}
	if !admin.Contains(netip.MustParseAddr(TunnelIP)) {
		t.Errorf("tunnel address %s is not admin", TunnelIP)
	}
}

// Agent peers have unique names and fixed, unique addresses in the agent
// half, and their secrets are named after them.
func TestAgentPeers(t *testing.T) {
	agent := netip.MustParsePrefix(AgentCIDR)
	names, addrs := map[string]bool{}, map[string]bool{}
	for _, p := range AgentPeers {
		a, err := netip.ParseAddr(p.Address)
		if err != nil || !agent.Contains(a) || a == agent.Addr() || a.As4()[3] == 255 {
			t.Errorf("peer %s at %q, not a host in %s", p.Name, p.Address, AgentCIDR)
		}
		if names[p.Name] || addrs[p.Address] {
			t.Errorf("peer %s at %s twice", p.Name, p.Address)
		}
		names[p.Name], addrs[p.Address] = true, true
		if p.Secret != "wireguard-"+p.Name+"-peer" {
			t.Errorf("peer %s publishes to %s", p.Name, p.Secret)
		}
		if p.Reader != "" && !strings.HasSuffix(p.Reader, ".iam.gserviceaccount.com") {
			t.Errorf("peer %s reader %q is not a service account", p.Name, p.Reader)
		}
	}
	if len(AgentPeers) == 0 {
		t.Fatal("no agent peers")
	}
}

// scripts/bootstrap.sh lets each agent peer's reader read that one secret,
// and nothing else reads one.
func TestBootstrapGrantsAgentReaders(t *testing.T) {
	b, err := os.ReadFile("../../../scripts/bootstrap.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?ms)^agent_readers=\(\n(.*?)^\)$`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatal("bootstrap.sh has no agent_readers=( ... ) list")
	}
	var got, want []string
	for _, l := range strings.Split(strings.TrimSpace(m[1]), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			got = append(got, l)
		}
	}
	for _, p := range AgentPeers {
		if p.Reader != "" {
			want = append(want, p.Secret+"="+p.Reader)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("bootstrap.sh agent_readers = %v, want %v", got, want)
	}
}

// Every bucket's key must be a known key, and only the log archive and the
// backups may be write-only: Loki, Mimir and Tempo read back what they store.
func TestBucketsUseKnownKeys(t *testing.T) {
	known := map[string]bool{}
	for _, k := range Keys {
		known[k] = true
	}
	for _, b := range Buckets {
		if !known[b.Key] {
			t.Errorf("bucket %s uses unknown key %q", b.Suffix, b.Key)
		}
		if b.WriteOnly != (b.Suffix == BucketLogArchive || b.Suffix == BucketPostgresBackups) {
			t.Errorf("bucket %s is write-only", b.Suffix)
		}
	}
}

// Lifecycle is a safety net behind application retention, never ahead of it.
func TestLifecycleNeverUndercutsRetention(t *testing.T) {
	retention := map[string]int{
		"loki":             RetentionLokiDays,
		"mimir-blocks":     RetentionMimirDays,
		"tempo":            RetentionTempoDays,
		"logs-archive":     RetentionLogArchiveDays,
		"postgres-backups": RetentionPostgresBackupDays,
	}
	for _, b := range Buckets {
		r, ok := retention[b.Suffix]
		if !ok {
			if b.LifecycleDays != 0 {
				t.Errorf("bucket %s has lifecycle but no retention", b.Suffix)
			}
			continue
		}
		if b.LifecycleDays < r {
			t.Errorf("bucket %s expires at %dd, before its %dd retention", b.Suffix, b.LifecycleDays, r)
		}
	}
	if RetentionLogArchiveDays != 90 {
		t.Errorf("log archive retention %d, want 90", RetentionLogArchiveDays)
	}
	if RetentionPostgresBackupDays != 90 {
		t.Errorf("Postgres backup retention %d, want 90", RetentionPostgresBackupDays)
	}
}

// GDPR erasure records must outlive the logs they erased.
func TestGDPRRecordsNeverExpire(t *testing.T) {
	for _, b := range Buckets {
		if b.Suffix != "logs-archive" {
			continue
		}
		for _, p := range b.LifecyclePrefixes {
			if p == ArchivePrefixGDPR {
				t.Error("gdpr-audit/ expires")
			}
		}
		if len(b.LifecyclePrefixes) != 3 {
			t.Errorf("archive lifecycle prefixes %v", b.LifecyclePrefixes)
		}
	}
}

// Secret ids are unique and fit the setup action's `secrets:` lines.
func TestSecretIDs(t *testing.T) {
	seen := map[string]bool{}
	valid := regexp.MustCompile(`^[a-z0-9-]{1,255}$`)
	for _, id := range Secrets() {
		if seen[id] {
			t.Errorf("Secrets() lists %s twice", id)
		}
		seen[id] = true
		if !valid.MatchString(id) {
			t.Errorf("secret id %q", id)
		}
	}
}

// The deploy workflow reads every secret but the owner-only ones, and
// nothing else. scripts/bootstrap.sh creates and grants exactly what it
// reads (`secret.sh deploy-ids`), so a secret it missed would fail the
// deploy that first needs it.
func TestWorkflowReadsEverySecret(t *testing.T) {
	b, err := os.ReadFile("../../../.gitea/workflows/deploy.yml")
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, id := range Secrets() {
		known[id] = true
	}
	ownerOnly := map[string]bool{}
	for _, id := range OwnerOnlySecrets {
		if !known[id] {
			t.Errorf("owner-only %s is not in Secrets()", id)
		}
		ownerOnly[id] = true
	}
	written := map[string]bool{}
	for _, id := range DeployWrittenSecrets {
		if !known[id] {
			t.Errorf("deploy-written %s is not in Secrets()", id)
		}
		written[id] = true
	}
	readBack := map[string]bool{}
	for _, id := range DeployReadBackSecrets {
		if !written[id] {
			t.Errorf("read-back %s is not in DeployWrittenSecrets", id)
		}
		readBack[id] = true
	}
	// The setup action's `secrets:` lines: NAME=id or @NAME=id, optional
	// with a leading ?.
	line := regexp.MustCompile(`(?m)^\s+\??@?[A-Z][A-Z0-9_]*=([a-z0-9-]+)\s*$`)
	matches := line.FindAllStringSubmatch(string(b), -1)
	if len(matches) == 0 {
		t.Fatal("deploy.yml reads no secrets through the setup action")
	}
	read := map[string]bool{}
	for _, m := range matches {
		read[m[1]] = true
		if !known[m[1]] {
			t.Errorf("deploy.yml reads %s, which is not a known secret", m[1])
		}
		// The deployer is never granted these: the image job gets the push
		// key as its own Actions secret, and only the owner manages checks.
		if ownerOnly[m[1]] {
			t.Errorf("deploy.yml reads owner-only %s through the deployer", m[1])
		}
		// The deployer may add to these, and read back only its own.
		if written[m[1]] && !readBack[m[1]] {
			t.Errorf("deploy.yml reads %s, which the deploy only writes", m[1])
		}
	}
	for _, id := range Secrets() {
		if !read[id] && !ownerOnly[id] && !written[id] {
			t.Errorf("deploy.yml never reads %s, so bootstrap.sh would not create or grant it", id)
		}
	}
}

// scripts/bootstrap.sh grants the deployer secretVersionAdder on every
// secret the deploy writes; a missing grant fails the first deploy late.
func TestBootstrapGrantsDeployWrittenSecrets(t *testing.T) {
	b, err := os.ReadFile("../../../scripts/bootstrap.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^deploy_written=\(([a-z0-9 -]*)\)$`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatal("bootstrap.sh has no deploy_written=(...) list")
	}
	got := strings.Fields(m[1])
	if !reflect.DeepEqual(got, DeployWrittenSecrets) {
		t.Errorf("bootstrap.sh deploy_written = %v, want %v", got, DeployWrittenSecrets)
	}
	m = regexp.MustCompile(`(?m)^deploy_read_back=\(([a-z0-9 -]*)\)$`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatal("bootstrap.sh has no deploy_read_back=(...) list")
	}
	if got := strings.Fields(m[1]); !reflect.DeepEqual(got, DeployReadBackSecrets) {
		t.Errorf("bootstrap.sh deploy_read_back = %v, want %v", got, DeployReadBackSecrets)
	}
}

// scripts/bootstrap.sh makes the bastion the inventory names: the deploy
// and scripts/ssh-config.sh would look for another VM.
func TestBootstrapMakesTheBastion(t *testing.T) {
	b, err := os.ReadFile("../../../scripts/bootstrap.sh")
	if err != nil {
		t.Fatal(err)
	}
	for v, want := range map[string]string{"BASTION": BastionName, "BASTION_ZONE": BastionZone} {
		m := regexp.MustCompile(`(?m)^` + v + `="([^"]*)"$`).FindStringSubmatch(string(b))
		if m == nil || m[1] != want {
			t.Errorf("bootstrap.sh %s = %v, want %q", v, m, want)
		}
	}
}

// scripts/bootstrap.sh makes the reader service account gitea's stacks
// grant: under another name, their bindings would name an account that
// doesn't exist.
func TestBootstrapMakesTheReader(t *testing.T) {
	b, err := os.ReadFile("../../../scripts/bootstrap.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^ensure_sa ` + ReaderSA + ` "`).Match(b) {
		t.Errorf("bootstrap.sh does not ensure_sa %s", ReaderSA)
	}
}

// ci.yml and deploy.yml build every image in build/ and nothing else: an
// image missing from deploy.yml would never reach the registry, and the
// hosts job would install a tag that isn't there.
func TestImageMatricesMatchBuildDirs(t *testing.T) {
	dockerfiles, err := filepath.Glob("../../../build/*/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, f := range dockerfiles {
		want = append(want, filepath.Base(filepath.Dir(f)))
	}
	if len(want) == 0 {
		t.Fatal("no build/*/Dockerfile")
	}
	matrix := regexp.MustCompile(`(?m)^\s+image: \[([a-z0-9, -]*)\]$`)
	for _, wf := range []string{"ci.yml", "deploy.yml"} {
		b, err := os.ReadFile("../../../.gitea/workflows/" + wf)
		if err != nil {
			t.Fatal(err)
		}
		m := matrix.FindStringSubmatch(string(b))
		if m == nil {
			t.Errorf("%s has no `image: [...]` matrix", wf)
			continue
		}
		got := strings.Split(m[1], ", ")
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s builds %v, want every build/ image %v", wf, got, want)
		}
	}
}

// The deploy's schedule and its Healthchecks.io check's agree: a check
// expecting a run that the schedule skips would alert every week.
func TestDeployScheduleMatchesItsCheck(t *testing.T) {
	wf, err := os.ReadFile("../../../.gitea/workflows/deploy.yml")
	if err != nil {
		t.Fatal(err)
	}
	hc, err := os.ReadFile("../../../scripts/healthchecks.sh")
	if err != nil {
		t.Fatal(err)
	}
	cron := regexp.MustCompile(`(?m)^\s+- cron: "([^"]+)"$`).FindAllStringSubmatch(string(wf), -1)
	if len(cron) != 1 {
		t.Fatalf("deploy.yml has %d schedules, want 1", len(cron))
	}
	check := regexp.MustCompile(`(?m)^DEPLOY_SCHEDULE="([^"]+)"`).FindStringSubmatch(string(hc))
	if check == nil {
		t.Fatal("healthchecks.sh has no DEPLOY_SCHEDULE")
	}
	if cron[0][1] != check[1] {
		t.Errorf("deploy.yml runs at %q, but its check expects %q", cron[0][1], check[1])
	}
}
