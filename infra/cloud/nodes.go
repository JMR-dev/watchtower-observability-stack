package main

import (
	_ "embed"
	"strings"

	"github.com/pulumi/pulumi-hcloud/sdk/go/hcloud"
	"github.com/pulumi/pulumi-tls/sdk/v5/go/tls"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

//go:embed cloud-init.yaml
var cloudInit string

type node struct {
	index     int
	name      string
	privateIP string
	server    *hcloud.Server
	hostKey   *tls.PrivateKey
}

// controlPlane reports whether the node carries etcd and the control plane.
func (n *node) controlPlane() bool { return n.index <= names.ControlPlaneNodes }

// newNodes creates the servers. Each keeps its own primary IPv4 and IPv6,
// which outlive the server, so rebuilding a node keeps its addresses (and
// its entries in the api.* record and the operators' known_hosts).
func newNodes(ctx *pulumi.Context, cfg *Config, p *providers, net *network) ([]*node, error) {
	opt := pulumi.Provider(p.hcloud)
	var nodes []*node
	for i := 1; i <= cfg.NodeCount; i++ {
		name := names.NodeName(i)
		nodeLabels := map[string]string{"role": names.NodeLabelRole, "node": name}

		v4, err := hcloud.NewPrimaryIp(ctx, name+"-ipv4", &hcloud.PrimaryIpArgs{
			Name:             pulumi.String(name + "-ipv4"),
			Type:             pulumi.String("ipv4"),
			Location:         pulumi.String(cfg.Location),
			AssigneeType:     pulumi.String("server"),
			AutoDelete:       pulumi.Bool(false),
			DeleteProtection: pulumi.Bool(cfg.DeleteProtection),
			Labels:           labels(nodeLabels),
		}, opt)
		if err != nil {
			return nil, err
		}
		v6, err := hcloud.NewPrimaryIp(ctx, name+"-ipv6", &hcloud.PrimaryIpArgs{
			Name:             pulumi.String(name + "-ipv6"),
			Type:             pulumi.String("ipv6"),
			Location:         pulumi.String(cfg.Location),
			AssigneeType:     pulumi.String("server"),
			AutoDelete:       pulumi.Bool(false),
			DeleteProtection: pulumi.Bool(cfg.DeleteProtection),
			Labels:           labels(nodeLabels),
		}, opt)
		if err != nil {
			return nil, err
		}

		hostKey, err := tls.NewPrivateKey(ctx, name+"-ssh-host", &tls.PrivateKeyArgs{
			Algorithm: pulumi.String("ED25519"),
		}, pulumi.Provider(p.tls))
		if err != nil {
			return nil, err
		}

		privateIP := names.PrivateIP(i)
		server, err := hcloud.NewServer(ctx, name, &hcloud.ServerArgs{
			Name:             pulumi.String(name),
			ServerType:       pulumi.String(cfg.ServerType),
			Image:            pulumi.String(cfg.Image),
			Location:         pulumi.String(cfg.Location),
			PlacementGroupId: intID(net.placement.ID()),
			SshKeys:          pulumi.StringArray{net.sshKey.ID().ToStringOutput()},
			UserData:         userData(hostKey),
			Labels:           labels(nodeLabels),
			PublicNets: hcloud.ServerPublicNetArray{
				&hcloud.ServerPublicNetArgs{
					Ipv4Enabled: pulumi.Bool(true),
					Ipv4:        intID(v4.ID()),
					Ipv6Enabled: pulumi.Bool(true),
					Ipv6:        intID(v6.ID()),
				},
			},
			Networks: hcloud.ServerNetworkTypeArray{
				&hcloud.ServerNetworkTypeArgs{
					NetworkId: intID(net.network.ID()),
					Ip:        pulumi.String(privateIP),
				},
			},
			// Hetzner requires the two to match.
			DeleteProtection:       pulumi.Bool(cfg.DeleteProtection),
			RebuildProtection:      pulumi.Bool(cfg.DeleteProtection),
			ShutdownBeforeDeletion: pulumi.Bool(true),
		}, opt,
			// A server attached to the network before its subnet exists fails.
			pulumi.DependsOn([]pulumi.Resource{net.subnet, net.firewall}),
			// Cloud-init runs once; Ansible owns the host after that. A
			// renamed image or a rotated key must not replace a node.
			pulumi.IgnoreChanges([]string{"userData", "sshKeys", "image"}),
		)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, &node{index: i, name: name, privateIP: privateIP, server: server, hostKey: hostKey})
	}
	return nodes, nil
}

// userData is cloud-init with the node's SSH host key, a secret: it carries
// the private half.
func userData(key *tls.PrivateKey) pulumi.StringOutput {
	rendered := pulumi.All(key.PrivateKeyOpenssh, key.PublicKeyOpenssh).ApplyT(func(v []interface{}) string {
		return renderCloudInit(v[0].(string), v[1].(string))
	}).(pulumi.StringOutput)
	return pulumi.ToSecret(rendered).(pulumi.StringOutput)
}

func renderCloudInit(private, public string) string {
	indented := "    " + strings.ReplaceAll(strings.TrimSpace(private), "\n", "\n    ")
	return strings.NewReplacer(
		"{{HOST_KEY_PRIVATE}}", indented,
		"{{HOST_KEY_PUBLIC}}", strings.TrimSpace(public),
	).Replace(cloudInit)
}

// knownHosts is the known_hosts file Ansible checks the nodes against.
func knownHosts(nodes []*node) pulumi.StringOutput {
	var parts []interface{}
	for _, n := range nodes {
		parts = append(parts, n.server.Ipv4Address, n.hostKey.PublicKeyOpenssh)
	}
	return pulumi.All(parts...).ApplyT(func(v []interface{}) string {
		var b strings.Builder
		for i, n := range nodes {
			b.WriteString(v[2*i].(string) + "," + n.name + " " + strings.TrimSpace(v[2*i+1].(string)) + "\n")
		}
		return b.String()
	}).(pulumi.StringOutput)
}

// newFloatingIP is the VPN's public address. It starts on the first node;
// after that fipd (../../fipd) moves it to whichever node runs the edge pod,
// so Pulumi ignores the assignment and never moves it back.
func newFloatingIP(ctx *pulumi.Context, cfg *Config, p *providers, first *node) (*hcloud.FloatingIp, error) {
	return hcloud.NewFloatingIp(ctx, "watchtower-vpn", &hcloud.FloatingIpArgs{
		Name:             pulumi.String("watchtower-vpn"),
		Type:             pulumi.String("ipv4"),
		HomeLocation:     pulumi.String(cfg.Location),
		ServerId:         intID(first.server.ID()),
		Description:      pulumi.String("WireGuard endpoint " + names.VPNHost + "; assignment owned by fipd"),
		DeleteProtection: pulumi.Bool(cfg.DeleteProtection),
		Labels:           labels(map[string]string{"role": names.FloatingIPLabel}),
	}, pulumi.Provider(p.hcloud),
		pulumi.IgnoreChanges([]string{"serverId"}),
		// Peers have this address in their configs. Losing it means
		// re-issuing every peer.
		pulumi.Protect(true),
	)
}
