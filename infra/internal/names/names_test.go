package names

import (
	"os"
	"regexp"
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
	// The setup action's `secrets:` lines: NAME=id or @NAME=id.
	line := regexp.MustCompile(`(?m)^\s+@?[A-Z][A-Z0-9_]*=([a-z0-9-]+)\s*$`)
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
	}
	for _, id := range Secrets() {
		if !read[id] && !ownerOnly[id] {
			t.Errorf("deploy.yml never reads %s, so bootstrap.sh would not create or grant it", id)
		}
	}
}
