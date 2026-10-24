package names

import "testing"

func TestNamesAreStable(t *testing.T) {
	for got, want := range map[string]string{
		BucketName("p", "loki"): "p-loki",
		NodeName(2):             "watchtower-2",
		PrivateIP(3):            "10.20.1.13",
		VPNHost:                 "vpn.watchtower.jasonmross.dev",
		APIHost:                 "api.watchtower.jasonmross.dev",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

// Every bucket's key must be a known component key, and only the log archive
// may be write-only: Loki, Mimir and Tempo read back what they store.
func TestBucketsUseKnownKeys(t *testing.T) {
	known := map[string]bool{}
	for _, k := range Keys {
		known[k] = true
	}
	for _, b := range Buckets {
		if !known[b.Key] {
			t.Errorf("bucket %s uses unknown key %q", b.Suffix, b.Key)
		}
		if b.WriteOnly && b.Suffix != "logs-archive" {
			t.Errorf("bucket %s is write-only", b.Suffix)
		}
	}
}

// Lifecycle is a safety net behind application retention, never ahead of it.
func TestLifecycleNeverUndercutsRetention(t *testing.T) {
	retention := map[string]int{
		"loki":         RetentionLokiDays,
		"mimir-blocks": RetentionMimirDays,
		"tempo":        RetentionTempoDays,
		"logs-archive": RetentionLogArchiveDays,
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
