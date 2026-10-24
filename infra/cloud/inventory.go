package main

import (
	"github.com/pulumi/pulumi-hcloud/sdk/go/hcloud"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type obj = map[string]interface{}

// inventoryJSON renders the Ansible inventory Kubespray builds the cluster
// from (JSON is valid YAML, so it is saved as hosts.yml):
//
//   - nodes 1-3 carry the control plane and etcd as well as workloads;
//   - nodes 4 and up are workers only, added with Kubespray's scale.yml
//     (growing etcd is a different procedure);
//   - Kubespray binds etcd and the API server to `ip`, the private address,
//     and Ansible connects over `ansible_host`, the public one.
func inventoryJSON(nodes []*node, fip *hcloud.FloatingIp) pulumi.StringOutput {
	var addrs []interface{}
	for _, n := range nodes {
		addrs = append(addrs, n.server.Ipv4Address)
	}
	addrs = append(addrs, fip.IpAddress)

	return pulumi.All(addrs...).ApplyT(func(vals []interface{}) (string, error) {
		hosts, controlPlane, workers := obj{}, obj{}, obj{}
		for i, n := range nodes {
			public := vals[i].(string)
			hosts[n.name] = obj{
				"ansible_host":           public,
				"ip":                     n.privateIP,
				"access_ip":              n.privateIP,
				"watchtower_public_ipv4": public,
			}
			workers[n.name] = obj{}
			if n.controlPlane() {
				controlPlane[n.name] = obj{}
			}
		}
		inv := obj{"all": obj{
			"vars": obj{
				"ansible_user":               "root",
				"ansible_python_interpreter": "/usr/bin/python3",
				// Every node carries it on eth0, so whichever node Hetzner
				// routes it to (fipd's choice) accepts the traffic.
				"watchtower_floating_ipv4": vals[len(vals)-1].(string),
			},
			"hosts": hosts,
			"children": obj{
				"kube_control_plane": obj{"hosts": controlPlane},
				"etcd":               obj{"hosts": controlPlane},
				"kube_node":          obj{"hosts": workers},
				"k8s_cluster":        obj{"children": obj{"kube_control_plane": obj{}, "kube_node": obj{}}},
			},
		}}
		b, err := marshalJSON(inv)
		return string(b), err
	}).(pulumi.StringOutput)
}
