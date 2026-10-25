package main

import (
	"strconv"

	"github.com/pulumi/pulumi-hcloud/sdk/go/hcloud"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

type network struct {
	network   *hcloud.Network
	subnet    *hcloud.NetworkSubnet
	placement *hcloud.PlacementGroup
	sshKey    *hcloud.SshKey
	// firewalls is keyed by host role.
	firewalls map[string]*hcloud.Firewall
}

// newNetwork creates what every host shares: the private network (it carries
// wg1, the WireGuard mesh all traffic between the servers goes through), the
// spread placement group (no two hosts on one physical machine), the SSH key
// and the two firewalls.
func newNetwork(ctx *pulumi.Context, cfg *Config, p *providers) (*network, error) {
	opt := pulumi.Provider(p.hcloud)

	nw, err := hcloud.NewNetwork(ctx, "watchtower-net", &hcloud.NetworkArgs{
		Name:    pulumi.String("watchtower"),
		IpRange: pulumi.String(names.NetworkCIDR),
		Labels:  labels(nil),
	}, opt)
	if err != nil {
		return nil, err
	}

	subnet, err := hcloud.NewNetworkSubnet(ctx, "watchtower-subnet", &hcloud.NetworkSubnetArgs{
		NetworkId:   intID(nw.ID()),
		Type:        pulumi.String("cloud"),
		NetworkZone: pulumi.String(cfg.NetworkZone),
		IpRange:     pulumi.String(names.SubnetCIDR),
	}, opt)
	if err != nil {
		return nil, err
	}

	pg, err := hcloud.NewPlacementGroup(ctx, "watchtower-spread", &hcloud.PlacementGroupArgs{
		Name:   pulumi.String("watchtower"),
		Type:   pulumi.String("spread"),
		Labels: labels(nil),
	}, opt)
	if err != nil {
		return nil, err
	}

	key, err := hcloud.NewSshKey(ctx, "watchtower-admin", &hcloud.SshKeyArgs{
		Name:      pulumi.String("watchtower-admin"),
		PublicKey: pulumi.String(cfg.SSHPublicKey),
		Labels:    labels(nil),
	}, opt)
	if err != nil {
		return nil, err
	}

	// The nodes take nothing on their public addresses: the deploy reaches
	// them through the proxy over the private network, people through the
	// VPN and then the proxy.
	nodes, err := newFirewall(ctx, p, "watchtower-nodes", names.RoleNode)
	if err != nil {
		return nil, err
	}
	// The proxy: SSH from the break-glass bastion only (the deploy and
	// people come in over the VPN), and WireGuard, since the tunnel ends
	// there.
	proxy, err := newFirewall(ctx, p, "watchtower-proxy", names.RoleProxy,
		rule("tcp", "22", "SSH (the break-glass bastion)", cfg.BreakGlassCIDRs),
		rule("udp", strconv.Itoa(names.PortWireGuard), "WireGuard", cfg.WireGuardCIDRs))
	if err != nil {
		return nil, err
	}

	return &network{
		network: nw, subnet: subnet, placement: pg, sshKey: key,
		firewalls: map[string]*hcloud.Firewall{names.RoleNode: nodes, names.RoleProxy: proxy},
	}, nil
}

// newFirewall is the only inbound policy on one role's public interfaces.
// Hetzner firewalls do not filter the private network; each host's nftables
// ruleset does (roles/firewall). It applies by label, so a host is covered
// from its first boot.
func newFirewall(ctx *pulumi.Context, p *providers, name, role string, rules ...*hcloud.FirewallRuleArgs) (*hcloud.Firewall, error) {
	all := hcloud.FirewallRuleArray{}
	for _, r := range rules {
		all = append(all, r)
	}
	all = append(all, &hcloud.FirewallRuleArgs{
		Direction:   pulumi.String("in"),
		Protocol:    pulumi.String("icmp"),
		Description: pulumi.String("ICMP"),
		SourceIps:   pulumi.ToStringArray([]string{"0.0.0.0/0", "::/0"}),
	})
	return hcloud.NewFirewall(ctx, name, &hcloud.FirewallArgs{
		Name:   pulumi.String(name),
		Labels: labels(nil),
		ApplyTos: hcloud.FirewallApplyToArray{
			&hcloud.FirewallApplyToArgs{LabelSelector: pulumi.String("role=" + role)},
		},
		Rules: all,
	}, pulumi.Provider(p.hcloud))
}

func rule(protocol, port, description string, sources []string) *hcloud.FirewallRuleArgs {
	return &hcloud.FirewallRuleArgs{
		Direction:   pulumi.String("in"),
		Protocol:    pulumi.String(protocol),
		Port:        pulumi.String(port),
		Description: pulumi.String(description),
		SourceIps:   pulumi.ToStringArray(sources),
	}
}
