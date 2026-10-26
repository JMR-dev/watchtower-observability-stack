package main

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

type obj = map[string]interface{}

// inventoryJSON renders the Ansible inventory (JSON is valid YAML, so it is
// saved as hosts.yml). Two groups, `proxy` and `nodes`. Ansible reaches the
// proxy on `public_ip` (or the tunnel address, from a VPN peer) and the nodes
// on `private_ip` through the proxy (scripts/ssh-config.sh);
// everything between the hosts goes over `mesh_ip` on wg1.
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
				"public_ip":  v[2*i].(string),
				"private_ip": h.privateIP,
				"mesh_ip":    h.meshIP,
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

		// No reader: that is granted in GCP, not on the hosts.
		var agents []obj
		for _, a := range names.AgentPeers {
			agents = append(agents, obj{"name": a.Name, "secret": a.Secret, "address": a.Address})
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
				// lists: SSH to the proxy's public address from the bastion,
				// WireGuard (proxy only) from wireguardAllowCidrs.
				"watchtower_break_glass_cidrs": cfg.BreakGlassCIDRs,
				// scripts/ssh-config.sh bastion: the way in through IAP.
				"watchtower_bastion": obj{
					"name":     names.BastionName,
					"zone":     names.BastionZone,
					"project":  cfg.GCPProject,
					"host_key": cfg.BastionHostKey,
				},
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
				// roles/edge makes the agent peers; roles/firewall and
				// Caddy hold them to the ingest endpoints and the tenant.
				"watchtower_admin_cidr":   names.AdminCIDR,
				"watchtower_agent_cidr":   names.AgentCIDR,
				"watchtower_agent_tenant": names.AgentTenant,
				"watchtower_agent_peers":  agents,

				"watchtower_s3_endpoint": names.S3Endpoint,
				"watchtower_s3_region":   names.S3Region,
				"watchtower_buckets":     buckets,
				"watchtower_archive_prefixes": obj{
					"containers": names.ArchivePrefixContainers,
					"journal":    names.ArchivePrefixJournal,
					"audit":      names.ArchivePrefixAudit,
				},
				"watchtower_postgres_backup_prefix": names.PostgresBackupPrefix,
				"watchtower_retention_days": obj{
					"loki":            names.RetentionLokiDays,
					"mimir":           names.RetentionMimirDays,
					"tempo":           names.RetentionTempoDays,
					"log_archive":     names.RetentionLogArchiveDays,
					"postgres_backup": names.RetentionPostgresBackupDays,
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
