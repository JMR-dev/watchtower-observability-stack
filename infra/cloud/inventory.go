package main

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

type obj = map[string]interface{}

// inventoryJSON renders the Ansible inventory (JSON is valid YAML, so it is
// saved as hosts.yml). Two groups, `proxy` and `nodes`. Ansible connects over
// `ansible_host`, the public IPv4; everything between the hosts goes over
// `mesh_ip` on wg1.
//
// Every name the roles need from internal/names travels here as a group var,
// so the playbooks never spell a bucket, an address or a retention period
// themselves.
func inventoryJSON(cfg *Config, hs *hosts) pulumi.StringOutput {
	var vals []interface{}
	for _, h := range hs.all() {
		vals = append(vals, h.server.Ipv4Address, intID(h.volume.ID()))
	}

	return pulumi.All(vals...).ApplyT(func(v []interface{}) (string, error) {
		vars := func(i int, h *host) obj {
			return obj{
				"ansible_host": v[2*i].(string),
				"private_ip":   h.privateIP,
				"mesh_ip":      h.meshIP,
				// roles/storage finds the volume as
				// /dev/disk/by-id/scsi-0HC_Volume_<id>.
				"volume_id": v[2*i+1].(int),
			}
		}
		proxy := obj{hs.proxy.name: vars(0, hs.proxy)}
		nodes := obj{}
		for i, n := range hs.nodes {
			hv := vars(i+1, n)
			hv["node_index"] = n.index
			hv["zone"] = n.zone()
			nodes[n.name] = hv
		}

		buckets := obj{}
		for _, b := range names.Buckets {
			buckets[b.Suffix] = names.BucketName(cfg.BucketPrefix, b.Suffix)
		}

		inv := obj{"all": obj{
			"vars": obj{
				"ansible_user":               "root",
				"ansible_python_interpreter": "/usr/bin/python3",

				// roles/firewall mirrors the Hetzner firewalls from the same
				// lists: SSH from admin and CI addresses, WireGuard (proxy
				// only) from wireguardAllowCidrs.
				"watchtower_admin_cidrs":     append(append([]string{}, cfg.AdminCIDRs...), cfg.CICIDRs...),
				"watchtower_wireguard_cidrs": cfg.WireGuardCIDRs,
				"watchtower_wireguard_port":  names.PortWireGuard,
				"watchtower_private_cidr":    names.SubnetCIDR,
				"watchtower_mesh_cidr":       names.MeshCIDR,
				"watchtower_mesh_port":       names.MeshPort,

				"watchtower_domain":      names.Domain,
				"watchtower_vpn_host":    names.VPNHost,
				"watchtower_tunnel_ip":   names.TunnelIP,
				"watchtower_tunnel_cidr": names.TunnelCIDR,
				"watchtower_gcp_project": cfg.GCPProject,

				"watchtower_s3_endpoint": names.S3Endpoint,
				"watchtower_s3_region":   names.S3Region,
				"watchtower_buckets":     buckets,
				"watchtower_archive_prefixes": obj{
					"containers": names.ArchivePrefixContainers,
					"journal":    names.ArchivePrefixJournal,
					"audit":      names.ArchivePrefixAudit,
				},
				"watchtower_retention_days": obj{
					"loki":        names.RetentionLokiDays,
					"mimir":       names.RetentionMimirDays,
					"tempo":       names.RetentionTempoDays,
					"log_archive": names.RetentionLogArchiveDays,
				},
			},
			"children": obj{
				"proxy": obj{"hosts": proxy},
				"nodes": obj{"hosts": nodes},
			},
		}}
		b, err := marshalJSON(inv)
		return string(b), err
	}).(pulumi.StringOutput)
}
