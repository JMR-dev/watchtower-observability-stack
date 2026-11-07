package names

import (
	"net/netip"
	"os"
	"os/exec"
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
	// Read by the bastion, never by the deploy: as off limits to it as those.
	for _, id := range BastionSecrets {
		if !known[id] {
			t.Errorf("bastion secret %s is not in Secrets()", id)
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
	if !regexp.MustCompile(`(?m)^ensure_sa ` + strings.TrimSuffix(BastionSA, "@"+GCPProject+".iam.gserviceaccount.com") + ` "`).Match(b) {
		t.Errorf("bootstrap.sh does not ensure_sa %s", BastionSA)
	}
}

// scripts/bastion-confirm.sh logs in to the bastion the inventory names, and
// leaves its file where the path unit in config/bastion/ruleset.sh watches: a
// confirmation that goes elsewhere rolls the ruleset back.
func TestBastionConfirmReachesTheBastion(t *testing.T) {
	b, err := os.ReadFile("../../../scripts/bastion-confirm.sh")
	if err != nil {
		t.Fatal(err)
	}
	r, err := os.ReadFile("../../../config/bastion/ruleset.sh")
	if err != nil {
		t.Fatal(err)
	}
	dropbox := regexp.MustCompile(`(?m)^DROPBOX="([^"]*)"$`).FindSubmatch(r)
	if dropbox == nil {
		t.Fatal("ruleset.sh has no DROPBOX")
	}
	for v, want := range map[string]string{
		"BASTION":      BastionName,
		"BASTION_ZONE": BastionZone,
		"GCP_PROJECT":  GCPProject,
		"DROPBOX":      string(dropbox[1]),
	} {
		m := regexp.MustCompile(`(?m)^` + v + `="([^"]*)"$`).FindStringSubmatch(string(b))
		if m == nil || m[1] != want {
			t.Errorf("bastion-confirm.sh %s = %v, want %q", v, m, want)
		}
	}
}

// The bastion's startup script reads the bastion's own agent peer: the one
// secret its service account may read.
func TestBastionReadsItsOwnPeer(t *testing.T) {
	b, err := os.ReadFile("../../../config/bastion/startup.sh")
	if err != nil {
		t.Fatal(err)
	}
	var want string
	for _, p := range AgentPeers {
		if p.Reader == BastionSA {
			want = "projects/" + GCPProject + "/secrets/" + p.Secret
		}
	}
	m := regexp.MustCompile(`(?m)^PEER_SECRET="([^"]*)"$`).FindStringSubmatch(string(b))
	if want == "" || m == nil || m[1] != want {
		t.Errorf("startup.sh PEER_SECRET = %v, want %q", m, want)
	}
}

// The bastion pings with the secret scripts/healthchecks.sh stores its check's
// URL in, and scripts/bootstrap.sh makes that secret and lets the bastion read it:
// under another name, the ping fails quietly and the check never starts.
func TestBastionReadsItsOwnPingURL(t *testing.T) {
	startup, err := os.ReadFile("../../../config/bastion/startup.sh")
	if err != nil {
		t.Fatal(err)
	}
	want := "projects/" + GCPProject + "/secrets/" + SecretHealthchecksBastionURL
	m := regexp.MustCompile(`(?m)^PING_SECRET="([^"]*)"$`).FindStringSubmatch(string(startup))
	if m == nil || m[1] != want {
		t.Errorf("startup.sh PING_SECRET = %v, want %q", m, want)
	}
	healthchecks, err := os.ReadFile("../../../scripts/healthchecks.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(healthchecks), `secret.sh" put `+SecretHealthchecksBastionURL) {
		t.Errorf("healthchecks.sh does not store %s", SecretHealthchecksBastionURL)
	}
	bootstrap, err := os.ReadFile("../../../scripts/bootstrap.sh")
	if err != nil {
		t.Fatal(err)
	}
	m = regexp.MustCompile(`(?m)^bastion_readable=\(([a-z0-9 -]*)\)$`).FindStringSubmatch(string(bootstrap))
	if m == nil {
		t.Fatal("bootstrap.sh has no bastion_readable=(...) list")
	}
	if got := strings.Fields(m[1]); !reflect.DeepEqual(got, BastionSecrets) {
		t.Errorf("bootstrap.sh bastion_readable = %v, want %v", got, BastionSecrets)
	}
}

// The deploy reads OptionalSecrets as optional (`?NAME=id`) and every other
// secret as required: a required read of a secret with no value yet fails the
// deploy, and an optional read of one it needs lets it run without.
func TestOptionalSecretsAreReadAsOptional(t *testing.T) {
	b, err := os.ReadFile("../../../.gitea/workflows/deploy.yml")
	if err != nil {
		t.Fatal(err)
	}
	optional := map[string]bool{}
	for _, id := range OptionalSecrets {
		optional[id] = true
	}
	seen := map[string]bool{}
	line := regexp.MustCompile(`(?m)^\s+(\??)@?[A-Z][A-Z0-9_]*=([a-z0-9-]+)\s*$`)
	for _, m := range line.FindAllStringSubmatch(string(b), -1) {
		seen[m[2]] = true
		if got := m[1] == "?"; got != optional[m[2]] {
			t.Errorf("deploy.yml reads %s with optional=%v, want %v", m[2], got, optional[m[2]])
		}
	}
	for _, id := range OptionalSecrets {
		if !seen[id] {
			t.Errorf("deploy.yml never reads optional %s", id)
		}
	}
}

// fakeGcloud answers `gcloud secrets versions access latest --secret ID ...
// --out-file F` the way Secret Manager does, by the id's first word: val- has a
// value, none- has no version, off- has its newest version disabled, denied- is
// a secret the caller may not read (or that doesn't exist: the same answer),
// token- is gcloud failing to authenticate at all.
const fakeGcloud = `#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  case "$1" in
    --secret) id=$2; shift 2 ;;
    --out-file) out=$2; shift 2 ;;
    *) shift ;;
  esac
done
case "$id" in
  val-*) printf 'value of %s' "$id" >"$out" ;;
  none-*) echo "ERROR: (gcloud.secrets.versions.access) NOT_FOUND: Secret [projects/1/secrets/${id}] not found or has no versions." >&2; exit 1 ;;
  off-*) echo "ERROR: (gcloud.secrets.versions.access) FAILED_PRECONDITION: Secret Version [projects/1/secrets/${id}/versions/2] is in DISABLED state." >&2; exit 1 ;;
  denied-*) echo "ERROR: (gcloud.secrets.versions.access) PERMISSION_DENIED: Permission 'secretmanager.versions.access' denied for resource 'projects/p/secrets/${id}/versions/latest' (or it may not exist)." >&2; exit 1 ;;
  token-*) echo "ERROR: (gcloud.secrets.versions.access) There was a problem refreshing your current auth tokens: ('invalid_grant: Invalid JWT Signature.')" >&2; exit 1 ;;
  *) echo "fake gcloud: unknown id ${id}" >&2; exit 2 ;;
esac
`

// readSecretsStep is the setup action's "Read secrets from Secret Manager"
// script, as the runner gets it.
func readSecretsStep(t *testing.T) string {
	b, err := os.ReadFile("../../../.gitea/actions/setup/action.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?ms)- name: Read secrets from Secret Manager\n.*?\n      run: \|\n((?:        .*\n|\n)+)`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatal("action.yml has no `Read secrets from Secret Manager` step with a run: | block")
	}
	return regexp.MustCompile(`(?m)^        `).ReplaceAllString(m[1], "")
}

// An optional secret (?NAME=id, ?@NAME=id) is skipped when it has no value (no
// version, or its newest disabled), and when the read is denied, which is also
// what a secret not yet made looks like to the deployer: a merge must not break
// every deploy until the owner runs bootstrap.sh. A denied read is never silent,
// though: a warning annotation names the secret. Any other error fails the job.
func TestSetupActionSkipsOnlyMissingOptionalSecrets(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	script := readSecretsStep(t)
	run := func(t *testing.T, secrets string) (env, output string, err error) {
		tmp := t.TempDir()
		bin := filepath.Join(tmp, "tools", "google-cloud-sdk", "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, "gcloud"), []byte(fakeGcloud), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmp, "gcp-deployer.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		envFile := filepath.Join(tmp, "github-env")
		// The repo's own step, from a file: bash runs what the runner would.
		stepFile := filepath.Join(tmp, "step.sh")
		if err := os.WriteFile(stepFile, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", stepFile)
		cmd.Env = append(os.Environ(), "RUNNER_TEMP="+tmp, "GITHUB_ENV="+envFile, "PROJECT=p", "SECRETS="+secrets)
		// The job log: stdout (where workflow commands go) and stderr.
		var out strings.Builder
		cmd.Stdout = &out
		cmd.Stderr = &out
		err = cmd.Run()
		b, _ := os.ReadFile(envFile)
		return string(b), out.String(), err
	}

	t.Run("no version or a disabled one: unset, and the job goes on", func(t *testing.T) {
		env, stderr, err := run(t, "?OPT=none-a\n?@OPT_FILE=off-b\nREQ=val-c\n")
		if err != nil {
			t.Fatalf("failed: %v\n%s", err, stderr)
		}
		if strings.Contains(env, "OPT") || !strings.Contains(env, "REQ=value of val-c\n") {
			t.Errorf("GITHUB_ENV = %q, want REQ alone", env)
		}
	})
	t.Run("an optional secret with a value is read like any other", func(t *testing.T) {
		env, stderr, err := run(t, "?OPT=val-d\n?@OPT_FILE=val-e\n")
		if err != nil {
			t.Fatalf("failed: %v\n%s", err, stderr)
		}
		if !strings.Contains(env, "OPT=value of val-d\n") || !regexp.MustCompile(`(?m)^OPT_FILE=.*/secrets/val-e$`).MatchString(env) {
			t.Errorf("GITHUB_ENV = %q", env)
		}
	})
	for _, line := range []string{"?OPT=denied-f", "?@OPT_FILE=denied-f"} {
		t.Run("a denied read of "+line+": unset, the job goes on, and a warning names it", func(t *testing.T) {
			env, output, err := run(t, line+"\nREQ=val-g\n")
			if err != nil {
				t.Fatalf("failed: %v\n%s", err, output)
			}
			if strings.Contains(env, "OPT") || !strings.Contains(env, "REQ=value of val-g\n") {
				t.Errorf("GITHUB_ENV = %q, want REQ alone", env)
			}
			warning := regexp.MustCompile(`(?m)^::warning[^:]*::denied-f can't be read \(PERMISSION_DENIED\).*scripts/bootstrap\.sh.*goes on without OPT`)
			if !warning.MatchString(output) {
				t.Errorf("no warning annotation naming denied-f, bootstrap.sh and OPT in the job log:\n%s", output)
			}
		})
	}
	for _, line := range []string{"?OPT=token-h", "?@OPT_FILE=token-h"} {
		t.Run("any other error reading "+line+" fails the job, naming the secret", func(t *testing.T) {
			env, output, err := run(t, line+"\n")
			if err == nil {
				t.Fatalf("succeeded; GITHUB_ENV = %q", env)
			}
			if !strings.Contains(output, "reading secret token-h") || !strings.Contains(output, "auth tokens") {
				t.Errorf("job log = %q", output)
			}
		})
	}
	t.Run("a required secret, with no version or denied, fails the job", func(t *testing.T) {
		for _, line := range []string{"REQ=none-i", "REQ=denied-j"} {
			if env, _, err := run(t, line+"\n"); err == nil {
				t.Errorf("%s succeeded; GITHUB_ENV = %q", line, env)
			}
		}
	})
}

// The telemetry alerts reach their Healthchecks.io check: the deploy reads the
// URL scripts/healthchecks.sh stores, under the name Ansible looks up, into
// watchtower_optional_secret (site.yml fails a deploy with any watchtower_secret
// empty); and Grafana's notifications open with the keywords the check sorts
// them by. Under another keyword the check would ignore every ping.
func TestTelemetryAlertsReachTheirCheck(t *testing.T) {
	read := func(path string) string {
		b, err := os.ReadFile("../../../" + path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	deploy := read(".gitea/workflows/deploy.yml")
	if !strings.Contains(deploy, "?HEALTHCHECKS_TELEMETRY_ALERT_URL="+SecretHealthchecksTelemetryAlertURL+"\n") {
		t.Errorf("deploy.yml does not read %s as HEALTHCHECKS_TELEMETRY_ALERT_URL", SecretHealthchecksTelemetryAlertURL)
	}
	secrets := read("ansible/inventory/group_vars/all/secrets.yml")
	optional := regexp.MustCompile(`(?ms)^watchtower_optional_secret:\n((?:[ #].*\n|\n)*)`).FindStringSubmatch(secrets)
	if optional == nil || !strings.Contains(optional[1], "lookup('ansible.builtin.env', 'HEALTHCHECKS_TELEMETRY_ALERT_URL', default='')") {
		t.Error("secrets.yml does not read HEALTHCHECKS_TELEMETRY_ALERT_URL into watchtower_optional_secret, empty when unset")
	}
	healthchecks := read("scripts/healthchecks.sh")
	if !strings.Contains(healthchecks, `secret.sh" put `+SecretHealthchecksTelemetryAlertURL) {
		t.Errorf("healthchecks.sh does not store %s", SecretHealthchecksTelemetryAlertURL)
	}
	// A deploy the deployer may not read it for only warns, so healthchecks.sh
	// says, as it stores it, whether bootstrap.sh has granted it, and never
	// grants it itself (bootstrap.sh owns IAM).
	if !strings.Contains(healthchecks, "gcloud secrets get-iam-policy "+SecretHealthchecksTelemetryAlertURL) ||
		!strings.Contains(healthchecks, "roles/secretmanager.secretAccessor") || !strings.Contains(healthchecks, "run scripts/bootstrap.sh") {
		t.Errorf("healthchecks.sh does not check that the deployer may read %s and point at bootstrap.sh", SecretHealthchecksTelemetryAlertURL)
	}
	if strings.Contains(healthchecks, "add-iam-policy-binding") || strings.Contains(healthchecks, "set-iam-policy") {
		t.Error("healthchecks.sh changes IAM: that is bootstrap.sh's")
	}
	for v, want := range map[string]string{"TELEMETRY_SUCCESS_KW": TelemetryAlertsResolved, "TELEMETRY_FAILURE_KW": TelemetryAlertsFiring} {
		m := regexp.MustCompile(`(?m)^` + v + `="([^"]*)"$`).FindStringSubmatch(healthchecks)
		if m == nil || m[1] != want {
			t.Errorf("healthchecks.sh %s = %v, want %q", v, m, want)
		}
	}
	notifications := read("ansible/roles/grafana/templates/telemetry-notifications.yaml.j2")
	for _, kw := range []string{TelemetryAlertsFiring, TelemetryAlertsResolved} {
		if n := strings.Count(notifications, kw); n != 1 {
			t.Errorf("telemetry-notifications.yaml.j2 holds %s %d times, want once", kw, n)
		}
	}
	if strings.Contains(TelemetryAlertsFiring, TelemetryAlertsResolved) || strings.Contains(TelemetryAlertsResolved, TelemetryAlertsFiring) {
		t.Error("one keyword holds the other, so a body could match both")
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

// The reader's key goes from scripts/rotate-gcp-key.sh, as that account, to the
// deploy, which reads it as optional: a deploy before the owner's steps must
// skip the pull, not fail. Not in the setup assert's watchtower_secret either,
// which fails on any value that is empty.
func TestReaderKeyIsWiredAndOptional(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	rotate := `(?m)^\s+reader\) SA_ID=` + ReaderSA + ` SECRET=` + SecretGCPTelemetryReaderKey + ` ;;$`
	if !regexp.MustCompile(rotate).MatchString(read("../../../scripts/rotate-gcp-key.sh")) {
		t.Errorf("rotate-gcp-key.sh does not map reader to %s and %s", ReaderSA, SecretGCPTelemetryReaderKey)
	}
	line := `(?m)^\s+\?@GCP_TELEMETRY_READER_KEY_FILE=` + SecretGCPTelemetryReaderKey + `$`
	if !regexp.MustCompile(line).MatchString(read("../../../.gitea/workflows/deploy.yml")) {
		t.Errorf("deploy.yml does not read %s as optional", SecretGCPTelemetryReaderKey)
	}
	secrets := read("../../../ansible/inventory/group_vars/all/secrets.yml")
	block := regexp.MustCompile(`(?ms)^watchtower_secret:\n(.*?)^\S`).FindStringSubmatch(secrets)
	if block == nil {
		t.Fatal("secrets.yml has no watchtower_secret block followed by another key")
	}
	if strings.Contains(block[1], "GCP_TELEMETRY_READER_KEY_FILE") {
		t.Error("the reader key is in watchtower_secret, so site.yml fails a deploy without it")
	}
	if !strings.Contains(secrets, "GCP_TELEMETRY_READER_KEY_FILE") {
		t.Error("secrets.yml does not read the reader key's file")
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
