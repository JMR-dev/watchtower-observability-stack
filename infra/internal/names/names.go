// Package names holds every name, address and retention period the cloud
// stack, the Ansible roles and the scripts must agree on. The cloud stack
// hands the ones Ansible needs on through the inventory it exports, so each is
// spelled here exactly once.
package names

import "fmt"

const (
	// Domain is the private ingest endpoint. Its A record is TunnelIP, so it
	// only resolves to something reachable from inside the WireGuard tunnel.
	Domain = "watchtower.jasonmross.dev"
	// VPNHost is where WireGuard peers connect: the proxy's primary IPv4.
	VPNHost = "vpn." + Domain

	// TunnelIP is wg0's address on the proxy; Caddy listens on it.
	TunnelIP = "10.8.0.1"
	// TunnelCIDR is the WireGuard peer range. Peers route only this range
	// through the tunnel (split tunnel), so the proxy forwards nothing.
	TunnelCIDR = "10.8.0.0/24"
	// AdminCIDR and AgentCIDR split it in two. Admin peers (people, the
	// deploy, and any peer made in the wg-easy UI, which numbers from the
	// bottom) reach everything on the tunnel address. Agent peers (the
	// services that ship telemetry, AgentPeers) reach only the ingest
	// endpoints, write only, into AgentTenant whatever tenant they ask for
	// (roles/firewall, roles/edge).
	AdminCIDR = "10.8.0.0/25"
	AgentCIDR = "10.8.0.128/25"
	// AgentTenant is the one tenant every agent writes to.
	AgentTenant = "jasonmross"

	// S3Endpoint and S3Region are Hetzner Object Storage in Falkenstein, the
	// servers' location. Everything (telemetry, log archive, backups, Pulumi
	// state) lives here.
	S3Endpoint = "fsn1.your-objectstorage.com"
	S3Region   = "fsn1"

	// GCPProject holds the DNS zone, the service accounts, the image
	// registry and every secret.
	GCPProject = "watchtower-observe"
)

// Host roles. Each is a Hetzner server label (`role=...`) and the Hetzner
// firewall for that role applies to it, so a new server is covered from its
// first boot.
const (
	RoleNode  = "watchtower-node"
	RoleProxy = "watchtower-proxy"
)

// ProxyName is the front box: Caddy and the WireGuard endpoint.
const ProxyName = "watchtower-proxy"

// ReaderSA is the service account watchtower reads Gitea CI's logs and
// metrics from GCP as (Pub/Sub and Cloud Monitoring, granted in gitea's own
// stacks). scripts/bootstrap.sh makes it, with no roles here and no key.
const ReaderSA = "watchtower-gcp-reader"

// The break-glass bastion, made by scripts/bootstrap.sh, not Pulumi: a GCE
// VM reached only through IAP, whose Cloud NAT address (breakGlassCidrs) the
// proxy admits for SSH. The way in when the VPN is down, and the deploy's
// when the proxy is rebuilt.
const (
	BastionName = "watchtower-bastion"
	BastionZone = "us-east1-b"
)

// NodeName is data node i (1-based).
func NodeName(i int) string {
	return fmt.Sprintf("watchtower-%d", i)
}

// MinNodes is the smallest cluster that survives losing a node: Loki and
// Mimir replicate three ways, and Kafka and etcd need a quorum of two.
const MinNodes = 3

// PrivateIP is a host's fixed address on the private network: the proxy is
// host 0, node i is host i.
func PrivateIP(host int) string {
	return fmt.Sprintf("10.20.1.%d", 10+host)
}

// MeshIP is a host's address on wg1, the WireGuard mesh that carries all
// traffic between the servers. Same numbering as PrivateIP.
func MeshIP(host int) string {
	return fmt.Sprintf("10.30.0.%d", 10+host)
}

// Network ranges and ports.
const (
	NetworkCIDR = "10.20.0.0/16"
	SubnetCIDR  = "10.20.1.0/24"
	MeshCIDR    = "10.30.0.0/24"
	// MeshPort is wg1's UDP port, reached over the private network only.
	MeshPort = 51830
	// PortWireGuard is the client VPN's UDP port on the proxy.
	PortWireGuard = 51820
)

// Secret Manager secrets in GCPProject. Each is also in gopass as
// watchtower/<id>. The deploy workflow reads every one but OwnerOnlySecrets
// (a test keeps it so), and scripts/bootstrap.sh creates and grants what it
// reads. Nothing secret is stack config.
const (
	// Read by the deploy workflow's cloud job.
	SecretPulumiPassphrase = "pulumi-passphrase"
	SecretHcloudToken      = "hcloud-token"

	// Read by the deploy workflow's hosts job and installed on the servers.
	SecretSSHPrivateKey               = "ssh-private-key"
	SecretLUKSPassphrase              = "luks-passphrase"
	SecretGARPullKey                  = "gar-pull-key"
	SecretGrafanaAdminPassword        = "grafana-admin-password"
	SecretGrafanaSecretKey            = "grafana-secret-key"
	SecretGrafanaDBPassword           = "grafana-db-password"
	SecretPostgresSuperuserPassword   = "postgres-superuser-password"
	SecretPostgresReplicationPassword = "postgres-replication-password"
	SecretPatroniRESTAPIPassword      = "patroni-restapi-password"
	SecretWGEasyPassword              = "wg-easy-password"
	SecretCaddyDNSKey                 = "caddy-dns-key"
	// The Healthchecks.io ping URL of the nightly Postgres backup
	// (ansible/roles/pgbackup): pinged on success, /fail on failure.
	SecretHealthchecksPGBackupURL = "healthchecks-pg-backup-url"
	// Every host's own Healthchecks.io ping URL, one JSON object of host
	// name to URL (scripts/healthchecks.sh); each host gets only its own
	// (ansible/roles/health).
	SecretHealthchecksHostURLs = "healthchecks-host-urls"
	// The Healthchecks.io ping URL of the deploy (scripts/healthchecks.sh):
	// every run pings it, /fail when a job failed, and the daily run's
	// absence alerts too.
	SecretHealthchecksDeployURL = "healthchecks-deploy-url"

	// SecretGARPushKey is copied to the GAR_PUSH_KEY Actions secret by the
	// owner (scripts/secret.sh gitea). The deployer is never granted it.
	SecretGARPushKey = "gar-push-key"
	// SecretHealthchecksAPIKey manages the checks in the Healthchecks.io
	// project (scripts/healthchecks.sh). Owner only: the deploy gets ping
	// URLs, never a key that could pause or delete checks.
	SecretHealthchecksAPIKey = "healthchecks-jasonmross-dev-api-key"

	// SecretWireGuardOwnerPeer is the owner's first WireGuard peer config,
	// which the deploy creates in wg-easy and adds here (ansible/roles/edge);
	// the owner fetches it with `scripts/secret.sh pull`. The deployer may
	// add versions but never read one.
	SecretWireGuardOwnerPeer = "wireguard-owner-peer"
	// SecretWireGuardDeployPeer is the deploy's own WireGuard peer config,
	// which the deploy creates in wg-easy like the owner's, and reads back:
	// its way to the proxy over the VPN.
	SecretWireGuardDeployPeer = "wireguard-deploy-peer"
)

// AgentPeer is the WireGuard peer of one service that ships its telemetry to
// watchtower (docs/client-telemetry.md). The deploy creates it in wg-easy at
// Address and adds its config to Secret, like the owner's peer: it may add
// versions but never read one. Reader is the one identity, in the service's
// own project, that scripts/bootstrap.sh lets read Secret; none yet means
// nothing can.
type AgentPeer struct {
	Name, Secret, Address, Reader string
}

// AgentPeers are the agent peers, each at a fixed address in AgentCIDR.
var AgentPeers = []AgentPeer{
	// Fetched at boot by the bastion's own service account (made later).
	{"bastion", "wireguard-bastion-peer", "10.8.0.129", ""},
	// Fetched on the VM by its service account.
	{"gitea-vm", "wireguard-gitea-vm-peer", "10.8.0.130", "gitea-vm@gitea-496920.iam.gserviceaccount.com"},
	// Fetched by the deploy job, as the deployer of that project.
	{"vaultwarden-production", "wireguard-vaultwarden-production-peer", "10.8.0.131", "vaultwarden-deployer@vaultwarden-497422.iam.gserviceaccount.com"},
	{"vaultwarden-disposable", "wireguard-vaultwarden-disposable-peer", "10.8.0.132", "vaultwarden-deployer@vaultwarden-497422.iam.gserviceaccount.com"},
	{"silverbullet-vm", "wireguard-silverbullet-vm-peer", "10.8.0.133", "cb-infra@silver-bullet-dev.iam.gserviceaccount.com"},
	// Fetched on the VM by its service account.
	{"blog-vm", "wireguard-blog-vm-peer", "10.8.0.134", "blog-vm@dev-blog-494815.iam.gserviceaccount.com"},
}

func agentSecrets() []string {
	var out []string
	for _, p := range AgentPeers {
		out = append(out, p.Secret)
	}
	return out
}

// DeployWrittenSecrets are written by the deploy, and read by it only if
// also in DeployReadBackSecrets:
// scripts/bootstrap.sh grants the deployer secretVersionAdder on each.
var DeployWrittenSecrets = append([]string{SecretWireGuardOwnerPeer, SecretWireGuardDeployPeer}, agentSecrets()...)

// DeployReadBackSecrets are deploy-written secrets the deploy also reads:
// scripts/bootstrap.sh grants the deployer secretAccessor on each, too.
var DeployReadBackSecrets = []string{SecretWireGuardDeployPeer}

// OwnerOnlySecrets are never read by the deploy, so never granted to the
// deployer (scripts/bootstrap.sh grants what deploy.yml reads).
var OwnerOnlySecrets = []string{SecretGARPushKey, SecretHealthchecksAPIKey}

// S3AccessKeySecret and S3SecretKeySecret name the two secrets holding one
// Hetzner S3 credential: KeyAdmin or a Keys entry.
func S3AccessKeySecret(key string) string { return "s3-" + key + "-access-key" }
func S3SecretKeySecret(key string) string { return "s3-" + key + "-secret-key" }

// Secrets lists every secret.
func Secrets() []string {
	out := []string{
		SecretPulumiPassphrase, SecretHcloudToken,
		SecretSSHPrivateKey, SecretLUKSPassphrase, SecretGARPullKey,
		SecretGrafanaAdminPassword, SecretGrafanaSecretKey, SecretGrafanaDBPassword,
		SecretPostgresSuperuserPassword, SecretPostgresReplicationPassword, SecretPatroniRESTAPIPassword,
		SecretWGEasyPassword, SecretCaddyDNSKey, SecretHealthchecksPGBackupURL, SecretHealthchecksHostURLs,
		SecretHealthchecksDeployURL,
		SecretGARPushKey, SecretHealthchecksAPIKey,
		SecretWireGuardOwnerPeer, SecretWireGuardDeployPeer,
	}
	out = append(out, agentSecrets()...)
	for _, k := range append([]string{KeyAdmin}, Keys...) {
		out = append(out, S3AccessKeySecret(k), S3SecretKeySecret(k))
	}
	return out
}

// Retention, in days. Application retention is the erasure mechanism; bucket
// lifecycle (LifecycleDays) is only a safety net behind it.
const (
	RetentionLokiDays       = 30
	RetentionMimirDays      = 90
	RetentionTempoDays      = 30
	RetentionLogArchiveDays = 90
	// Nightly dumps of Grafana's database (ansible/roles/pgbackup). Here the
	// bucket lifecycle is the retention: nothing else deletes a dump.
	RetentionPostgresBackupDays = 90
)

// Bucket is one Hetzner Object Storage bucket and the S3 key allowed into it.
type Bucket struct {
	// Suffix is appended to the stack's bucketPrefix.
	Suffix string
	// Key names the S3 key (besides the admin key) that may use it.
	Key string
	// LifecycleDays expires objects after this many days; 0 means never.
	LifecycleDays int
	// WriteOnly limits Key to writing objects: it cannot read, list or delete.
	WriteOnly bool
	// LifecyclePrefixes scopes the expiry to these key prefixes; empty means
	// the whole bucket.
	LifecyclePrefixes []string
}

// Bucket suffixes other code refers to by name.
const (
	BucketLogArchive      = "logs-archive"
	BucketPostgresBackups = "postgres-backups"
)

// PostgresBackupPrefix is where the nightly dumps of Grafana's database go:
// grafana/grafana-<UTC yyyymmddThhmmssZ>.dump, so keys sort by time.
const PostgresBackupPrefix = "grafana/"

// Log-archive key prefixes: Fluent Bit writes the first three (and they
// expire), scripts/gdpr-purge.sh writes erasure records to the last (kept
// for good: they are the evidence an erasure happened).
const (
	ArchivePrefixContainers = "containers/"
	ArchivePrefixJournal    = "journal/"
	ArchivePrefixAudit      = "audit/"
	ArchivePrefixGDPR       = "gdpr-audit/"
)

// KeyAdmin is the S3 key Pulumi, the deploy workflow and operators use; every
// bucket admits it, and it alone may use the Pulumi state bucket.
const KeyAdmin = "admin"

// KeyCluster is the S3 key everything on the servers shares: Loki, Mimir,
// Tempo, Fluent Bit and the Postgres backup. Bucket policies keep it out of
// the Pulumi state bucket and let it only write to the log archive and the
// backups.
const KeyCluster = "cluster"

// Keys lists the non-admin keys.
var Keys = []string{KeyCluster}

// Buckets lists every bucket the cloud stack creates. The Pulumi state bucket
// is not here: scripts/bootstrap.sh creates it, because Pulumi needs it first.
var Buckets = []Bucket{
	{Suffix: "loki", Key: KeyCluster, LifecycleDays: 2 * RetentionLokiDays},
	{Suffix: "mimir-blocks", Key: KeyCluster, LifecycleDays: 2 * RetentionMimirDays},
	{Suffix: "mimir-ruler", Key: KeyCluster},
	{Suffix: "mimir-alertmanager", Key: KeyCluster},
	{Suffix: "tempo", Key: KeyCluster, LifecycleDays: 2 * RetentionTempoDays},
	{
		Suffix: BucketLogArchive, Key: KeyCluster, LifecycleDays: RetentionLogArchiveDays, WriteOnly: true,
		LifecyclePrefixes: []string{ArchivePrefixContainers, ArchivePrefixJournal, ArchivePrefixAudit},
	},
	// Write-only, so a node can add a dump but never read, list or delete
	// one; the operator restores with the admin key.
	{Suffix: BucketPostgresBackups, Key: KeyCluster, LifecycleDays: RetentionPostgresBackupDays, WriteOnly: true},
}

// BucketName joins a stack's bucket prefix and a suffix.
func BucketName(prefix, suffix string) string {
	return prefix + "-" + suffix
}
