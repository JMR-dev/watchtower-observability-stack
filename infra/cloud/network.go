package main

import (
	"github.com/pulumi/pulumi-hcloud/sdk/go/hcloud"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

type network struct {
	network   *hcloud.Network
	subnet    *hcloud.NetworkSubnet
	placement *hcloud.PlacementGroup
	sshKey    *hcloud.SshKey
	firewall  *hcloud.Firewall
}

// newNetwork creates what every node shares: the private network (etcd, the
// API server and pod traffic, which Cilium encrypts with WireGuard), the
// spread placement group (no two nodes on one physical host), the SSH key and
// the firewall.
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

	fw, err := newFirewall(ctx, cfg, p)
	if err != nil {
		return nil, err
	}

	return &network{network: nw, subnet: subnet, placement: pg, sshKey: key, firewall: fw}, nil
}

// newFirewall is the only inbound policy on the public interfaces, Floating
// IP included. Hetzner firewalls do not filter the private network, which
// carries the cluster's own traffic. It applies by label, so a node is
// covered from its first boot.
func newFirewall(ctx *pulumi.Context, cfg *Config, p *providers) (*hcloud.Firewall, error) {
	ops := append(append([]string{}, cfg.AdminCIDRs...), cfg.CICIDRs...)
	return hcloud.NewFirewall(ctx, "watchtower-nodes", &hcloud.FirewallArgs{
		Name:   pulumi.String("watchtower-nodes"),
		Labels: labels(nil),
		ApplyTos: hcloud.FirewallApplyToArray{
			&hcloud.FirewallApplyToArgs{LabelSelector: pulumi.String("role=" + names.NodeLabelRole)},
		},
		Rules: hcloud.FirewallRuleArray{
			rule("tcp", "22", "SSH (Ansible, operators)", ops),
			rule("tcp", "6443", "Kubernetes API (deploys, operators)", ops),
			// Any node may host the edge pod, so every node accepts WireGuard.
			rule("udp", "51820", "WireGuard", cfg.WireGuardCIDRs),
			&hcloud.FirewallRuleArgs{
				Direction:   pulumi.String("in"),
				Protocol:    pulumi.String("icmp"),
				Description: pulumi.String("ICMP"),
				SourceIps:   pulumi.ToStringArray([]string{"0.0.0.0/0", "::/0"}),
			},
		},
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
