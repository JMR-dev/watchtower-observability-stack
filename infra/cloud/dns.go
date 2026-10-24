package main

import (
	"fmt"

	"github.com/pulumi/pulumi-gcp/sdk/v10/go/gcp/dns"
	"github.com/pulumi/pulumi-hcloud/sdk/go/hcloud"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

// newRecords writes the zone's three records. The zone itself is not a Pulumi
// resource: scripts/bootstrap.sh creates and delegates it, the way every
// jasonmross.dev subdomain is set up, so `pulumi destroy` can never take DNS
// down.
//
//	watchtower.jasonmross.dev      A  10.8.0.1   private: only resolves to the tunnel
//	vpn.watchtower.jasonmross.dev  A  <Floating IP>  where peers connect
//	api.watchtower.jasonmross.dev  A  <control-plane nodes>
func newRecords(ctx *pulumi.Context, cfg *Config, p *providers, nodes []*node, fip *hcloud.FloatingIp) error {
	opt := pulumi.Provider(p.gcp)
	zone, err := dns.LookupManagedZone(ctx, &dns.LookupManagedZoneArgs{
		Name:    cfg.DNSZone,
		Project: &cfg.GCPProject,
	}, opt)
	if err != nil {
		return err
	}
	if zone.DnsName != names.Domain+"." {
		return fmt.Errorf("zone %s serves %q, not %s.", cfg.DNSZone, zone.DnsName, names.Domain)
	}

	var api pulumi.StringArray
	for _, n := range nodes {
		if n.controlPlane() {
			api = append(api, n.server.Ipv4Address)
		}
	}

	for _, r := range []struct {
		name, fqdn string
		rrdatas    pulumi.StringArrayInput
	}{
		{"watchtower-a", names.Domain, pulumi.StringArray{pulumi.String(names.TunnelIP)}},
		{"vpn-a", names.VPNHost, pulumi.StringArray{fip.IpAddress}},
		{"api-a", names.APIHost, api},
	} {
		if _, err := dns.NewRecordSet(ctx, r.name, &dns.RecordSetArgs{
			Project:     pulumi.String(cfg.GCPProject),
			ManagedZone: pulumi.String(zone.Name),
			Name:        pulumi.String(r.fqdn + "."),
			Type:        pulumi.String("A"),
			// Short enough that a rebuilt node or a moved address is not a
			// long outage, long enough not to hammer the resolvers.
			Ttl:     pulumi.Int(300),
			Rrdatas: r.rrdatas,
		}, opt); err != nil {
			return err
		}
	}
	return nil
}
