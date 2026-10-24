// Package names holds every name, port and retention period that the cloud and
// apps stacks must agree on. The two stacks never read each other's state (CI
// runs them as separate programs), so anything one creates and the other
// consumes is spelled here exactly once.
package names

import "fmt"

const (
	// Domain is the private ingest endpoint. Its A record is TunnelIP, so it
	// only resolves to something reachable from inside the WireGuard tunnel.
	Domain = "watchtower.jasonmross.dev"
	// VPNHost is where WireGuard peers connect: the Floating IP.
	VPNHost = "vpn." + Domain
	// APIHost fronts the Kubernetes API (round-robin over the control-plane
	// nodes, firewalled to admin and CI addresses).
	APIHost = "api." + Domain

	// TunnelIP is wg0's address inside the edge pod; Caddy listens on it.
	TunnelIP = "10.8.0.1"
	// TunnelCIDR is the WireGuard peer range. Peers route only this range
	// through the tunnel (split tunnel), so the edge pod forwards nothing.
	TunnelCIDR = "10.8.0.0/24"

	// S3Endpoint and S3Region are Hetzner Object Storage in the cluster's
	// location. Everything (telemetry, log archive, Pulumi state) lives here.
	S3Endpoint = "nbg1.your-objectstorage.com"
	S3Region   = "nbg1"

	// NodeLabelRole is the Hetzner server label every node carries. The
	// firewall applies to it, so a new node is covered from its first boot.
	NodeLabelRole = "watchtower"
	// FloatingIPLabel is the Hetzner label fipd finds the VPN Floating IP by.
	FloatingIPLabel = "watchtower-vpn"
)

// Kubernetes namespaces.
const (
	NamespaceApps    = "watchtower"
	NamespaceEdge    = "watchtower-edge"
	NamespaceFIP     = "watchtower-fip"
	NamespaceLogging = "logging"
)

// EdgeAppLabel selects the edge pod. fipd follows the node it runs on.
const EdgeAppLabel = "edge"

// Ports Caddy serves on TunnelIP, and the backends behind them.
const (
	PortGrafana   = 443
	PortLoki      = 3100
	PortMimir     = 8080
	PortTempo     = 3200
	PortOTLPGRPC  = 4317
	PortOTLPHTTP  = 4318
	PortWGUI      = 51821
	PortWireGuard = 51820
)

// Retention, in days. Application retention is the erasure mechanism; bucket
// lifecycle (LifecycleDays) is only a safety net behind it.
const (
	RetentionLokiDays       = 30
	RetentionMimirDays      = 90
	RetentionTempoDays      = 30
	RetentionLogArchiveDays = 90
)

// Bucket is one Hetzner Object Storage bucket and the S3 key allowed into it.
type Bucket struct {
	// Suffix is appended to the stack's bucketPrefix.
	Suffix string
	// Key names the component S3 key (besides the admin key) that may use it.
	Key string
	// LifecycleDays expires objects after this many days; 0 means never.
	LifecycleDays int
	// WriteOnly limits Key to writing objects: it cannot read, list or delete.
	WriteOnly bool
	// LifecyclePrefixes scopes the expiry to these key prefixes; empty means
	// the whole bucket.
	LifecyclePrefixes []string
}

// Log-archive key prefixes: Fluent Bit writes the first three (and they
// expire), scripts/gdpr-purge.sh writes erasure records to the last (kept
// for good: they are the evidence an erasure happened).
const (
	ArchivePrefixContainers = "containers/"
	ArchivePrefixJournal    = "journal/"
	ArchivePrefixAudit      = "audit/"
	ArchivePrefixGDPR       = "gdpr-audit/"
)

// Component S3 keys. Each is a separate Hetzner S3 credential.
const (
	KeyLoki    = "loki"
	KeyMimir   = "mimir"
	KeyTempo   = "tempo"
	KeyLogship = "logship"
)

// Keys lists the component keys in a fixed order.
var Keys = []string{KeyLoki, KeyMimir, KeyTempo, KeyLogship}

// Buckets lists every bucket the cloud stack creates. The Pulumi state bucket
// is not here: scripts/bootstrap.sh creates it, because Pulumi needs it first.
var Buckets = []Bucket{
	{Suffix: "loki", Key: KeyLoki, LifecycleDays: 2 * RetentionLokiDays},
	{Suffix: "mimir-blocks", Key: KeyMimir, LifecycleDays: 2 * RetentionMimirDays},
	{Suffix: "mimir-ruler", Key: KeyMimir},
	{Suffix: "mimir-alertmanager", Key: KeyMimir},
	{Suffix: "tempo", Key: KeyTempo, LifecycleDays: 2 * RetentionTempoDays},
	{
		Suffix: "logs-archive", Key: KeyLogship, LifecycleDays: RetentionLogArchiveDays, WriteOnly: true,
		LifecyclePrefixes: []string{ArchivePrefixContainers, ArchivePrefixJournal, ArchivePrefixAudit},
	},
}

// BucketName joins a stack's bucket prefix and a suffix.
func BucketName(prefix, suffix string) string {
	return prefix + "-" + suffix
}

// NodeName is the Hetzner server and Kubernetes node name of node i (1-based).
func NodeName(i int) string {
	return fmt.Sprintf("watchtower-%d", i)
}

// ControlPlaneNodes is how many nodes carry the control plane and etcd. Nodes
// beyond it are workers, added with Kubespray's scale.yml.
const ControlPlaneNodes = 3

// PrivateIP is node i's fixed address on the private network.
func PrivateIP(i int) string {
	return fmt.Sprintf("10.20.1.%d", 10+i)
}

// Private network ranges.
const (
	NetworkCIDR = "10.20.0.0/16"
	SubnetCIDR  = "10.20.1.0/24"
)
