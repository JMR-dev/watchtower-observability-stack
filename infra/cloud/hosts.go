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

// host is one server: the proxy (index 0) or data node i.
type host struct {
	index     int
	name      string
	role      string
	privateIP string
	meshIP    string
	server    *hcloud.Server
	hostKey   *tls.PrivateKey
	volume    *hcloud.Volume
}

// zone is the node's Tempo live-store zone: a, b, c...
func (h *host) zone() string { return string(rune('a' + h.index - 1)) }

type hosts struct {
	proxy *host
	nodes []*host
}

// all lists the proxy first, then the nodes in order.
func (hs *hosts) all() []*host { return append([]*host{hs.proxy}, hs.nodes...) }

// newHosts creates the proxy and the data nodes.
func newHosts(ctx *pulumi.Context, cfg *Config, p *providers, net *network) (*hosts, error) {
	proxy, err := newHost(ctx, cfg, p, net, 0, names.ProxyName, names.RoleProxy, cfg.ProxyServerType, cfg.ProxyVolumeGB)
	if err != nil {
		return nil, err
	}
	hs := &hosts{proxy: proxy}
	for i := 1; i <= cfg.NodeCount; i++ {
		n, err := newHost(ctx, cfg, p, net, i, names.NodeName(i), names.RoleNode, cfg.NodeServerType, cfg.NodeVolumeGB)
		if err != nil {
			return nil, err
		}
		hs.nodes = append(hs.nodes, n)
	}
	return hs, nil
}

// newHost creates one server with its own primary IPv4 and IPv6 and its data
// volume. The addresses and the volume outlive the server, so rebuilding a
// host keeps its addresses (the vpn record, peers' configs, known_hosts) and
// its data.
func newHost(ctx *pulumi.Context, cfg *Config, p *providers, net *network,
	index int, name, role, serverType string, volumeGB int,
) (*host, error) {
	opt := pulumi.Provider(p.hcloud)
	hostLabels := map[string]string{"role": role, "host": name}

	v4, err := hcloud.NewPrimaryIp(ctx, name+"-ipv4", &hcloud.PrimaryIpArgs{
		Name:             pulumi.String(name + "-ipv4"),
		Type:             pulumi.String("ipv4"),
		Location:         pulumi.String(cfg.Location),
		AssigneeType:     pulumi.String("server"),
		AutoDelete:       pulumi.Bool(false),
		DeleteProtection: pulumi.Bool(cfg.DeleteProtection),
		Labels:           labels(hostLabels),
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
		Labels:           labels(hostLabels),
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

	privateIP := names.PrivateIP(index)
	server, err := hcloud.NewServer(ctx, name, &hcloud.ServerArgs{
		Name:             pulumi.String(name),
		ServerType:       pulumi.String(serverType),
		Image:            pulumi.String(cfg.Image),
		Location:         pulumi.String(cfg.Location),
		PlacementGroupId: intID(net.placement.ID()),
		SshKeys:          pulumi.StringArray{net.sshKey.ID().ToStringOutput()},
		UserData:         userData(hostKey),
		Labels:           labels(hostLabels),
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
		// A server attached to the network before its subnet exists fails,
		// and one booted before its firewall exists is briefly unfiltered.
		pulumi.DependsOn([]pulumi.Resource{net.subnet, net.firewalls[role]}),
		// Cloud-init runs once; Ansible owns the host after that. A
		// renamed image or a rotated key must not replace a host.
		pulumi.IgnoreChanges([]string{"userData", "sshKeys", "image"}),
		// The account's vCPU cap leaves no room for a second server while
		// the old one exists, and a primary IP can only be assigned to one
		// server: a replacement has to delete first.
		pulumi.DeleteBeforeReplace(true),
	)
	if err != nil {
		return nil, err
	}

	volume, err := newVolume(ctx, cfg, p, name, volumeGB, hostLabels, server)
	if err != nil {
		return nil, err
	}

	return &host{
		index: index, name: name, role: role,
		privateIP: privateIP, meshIP: names.MeshIP(index),
		server: server, hostKey: hostKey, volume: volume,
	}, nil
}

// newVolume is the host's data volume, unformatted: Ansible (roles/storage)
// puts LUKS on it. Protected, because it holds the WALs, Kafka's log,
// Postgres and the proxy's certificates and peers.
func newVolume(ctx *pulumi.Context, cfg *Config, p *providers, name string, gb int,
	hostLabels map[string]string, server *hcloud.Server,
) (*hcloud.Volume, error) {
	opt := pulumi.Provider(p.hcloud)
	volume, err := hcloud.NewVolume(ctx, name+"-data", &hcloud.VolumeArgs{
		Name:             pulumi.String(name + "-data"),
		Size:             pulumi.Int(gb),
		Location:         pulumi.String(cfg.Location),
		Automount:        pulumi.Bool(false),
		DeleteProtection: pulumi.Bool(cfg.DeleteProtection),
		Labels:           labels(hostLabels),
	}, opt, pulumi.Protect(true))
	if err != nil {
		return nil, err
	}
	if _, err := hcloud.NewVolumeAttachment(ctx, name+"-data", &hcloud.VolumeAttachmentArgs{
		VolumeId:  intID(volume.ID()),
		ServerId:  intID(server.ID()),
		Automount: pulumi.Bool(false),
	}, opt); err != nil {
		return nil, err
	}
	return volume, nil
}

// userData is cloud-init with the host's SSH host key, a secret: it carries
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

// knownHosts is the known_hosts file Ansible checks every host against.
func knownHosts(all []*host) pulumi.StringOutput {
	var parts []interface{}
	for _, h := range all {
		parts = append(parts, h.server.Ipv4Address, h.hostKey.PublicKeyOpenssh)
	}
	return pulumi.All(parts...).ApplyT(func(v []interface{}) string {
		var b strings.Builder
		for i, h := range all {
			b.WriteString(v[2*i].(string) + "," + h.name + " " + strings.TrimSpace(v[2*i+1].(string)) + "\n")
		}
		return b.String()
	}).(pulumi.StringOutput)
}
