package main

import (
	"fmt"

	"github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes"
	"github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/apiextensions"
	metav1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/meta/v1"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

// Cilium network policies. Selecting every endpoint in a namespace with an
// ingress and an egress section puts the whole namespace into default deny
// in both directions; each rule below is an explicit allow. The kubelet's
// probes come from the node itself, which Cilium always allows.
//
// FQDN rules only work for names the pod resolved through Cilium's DNS proxy,
// which is why every policy's DNS rule carries an L7 `dns` match.

func endpointsIn(namespace string, labels obj) obj {
	m := obj{"k8s:io.kubernetes.pod.namespace": namespace}
	for k, v := range labels {
		m[k] = v
	}
	return obj{"matchLabels": m}
}

func ports(protocol string, ps ...int) []interface{} {
	var out []interface{}
	for _, p := range ps {
		out = append(out, obj{"port": fmt.Sprint(p), "protocol": protocol})
	}
	return []interface{}{obj{"ports": out}}
}

// dnsEgress allows kube-dns, through Cilium's DNS proxy.
func dnsEgress() obj {
	return obj{
		"toEndpoints": []interface{}{endpointsIn("kube-system", obj{"k8s:k8s-app": "kube-dns"})},
		"toPorts": []interface{}{obj{
			"ports": []interface{}{obj{"port": "53", "protocol": "UDP"}, obj{"port": "53", "protocol": "TCP"}},
			"rules": obj{"dns": []interface{}{obj{"matchPattern": "*"}}},
		}},
	}
}

// fqdnEgress allows HTTPS to the given names (exact, or patterns with *).
func fqdnEgress(port int, fqdns ...string) obj {
	var to []interface{}
	for _, f := range fqdns {
		to = append(to, obj{"matchPattern": f})
	}
	return obj{"toFQDNs": to, "toPorts": ports("TCP", port)}
}

// s3Egress reaches Hetzner Object Storage, path- or virtual-host-style.
func s3Egress() obj {
	return fqdnEgress(443, names.S3Endpoint, "*."+names.S3Endpoint)
}

// apiServerEgress reaches the Kubernetes API.
func apiServerEgress() obj {
	return obj{"toEntities": []interface{}{"kube-apiserver"}}
}

// denyAllIngress is an ingress section that admits nothing.
var denyAllIngress = []interface{}{obj{}}

type policy struct {
	name      string
	namespace pulumi.StringInput
	ingress   []interface{}
	egress    []interface{}
}

// grafanaPodPort is Grafana's container port. Cilium matches pod ports, after
// the Service (port 80) has been translated, so policies name this one.
const grafanaPodPort = 3000

func policies(ns *namespaces) []policy {
	backendPorts := ports("TCP", grafanaPodPort, names.PortLoki, names.PortMimir, names.PortTempo, names.PortOTLPGRPC, names.PortOTLPHTTP)
	return []policy{
		{
			// Loki, Mimir, Tempo, Grafana and the caches talk freely among
			// themselves (gossip, gRPC, queries); from outside, only the
			// edge pod reaches them, on the ports it proxies.
			name: "watchtower", namespace: ns.apps,
			ingress: []interface{}{
				obj{"fromEndpoints": []interface{}{endpointsIn(names.NamespaceApps, nil)}},
				obj{"fromEndpoints": []interface{}{endpointsIn(names.NamespaceEdge, nil)}, "toPorts": backendPorts},
			},
			egress: []interface{}{
				obj{"toEndpoints": []interface{}{endpointsIn(names.NamespaceApps, nil)}},
				dnsEgress(),
				s3Egress(),
			},
		},
		{
			// WireGuard from anywhere (the firewall narrows it); everything
			// else arrives through wg0 inside the pod, which this does not
			// see. Out: the backends, ACME, and Cloud DNS for DNS-01 (its
			// API, Google's token endpoint, and the zone's name servers,
			// which Caddy queries to check propagation).
			name: "edge", namespace: ns.edge,
			ingress: []interface{}{
				obj{"fromEntities": []interface{}{"world"}, "toPorts": ports("UDP", names.PortWireGuard)},
			},
			egress: []interface{}{
				obj{"toEndpoints": []interface{}{endpointsIn(names.NamespaceApps, nil)}, "toPorts": backendPorts},
				dnsEgress(),
				fqdnEgress(443, "acme-v02.api.letsencrypt.org", "dns.googleapis.com", "oauth2.googleapis.com", "www.googleapis.com"),
				obj{
					"toFQDNs": []interface{}{obj{"matchPattern": "*.googledomains.com"}},
					"toPorts": []interface{}{obj{"ports": []interface{}{obj{"port": "53", "protocol": "UDP"}, obj{"port": "53", "protocol": "TCP"}}}},
				},
			},
		},
		{
			// fipd: the API server and the Hetzner API, nothing in.
			name: "fipd", namespace: ns.fip,
			ingress: denyAllIngress,
			egress:  []interface{}{apiServerEgress(), dnsEgress(), fqdnEgress(443, "api.hetzner.cloud")},
		},
		{
			// Fluent Bit: pod metadata from the API server, then S3.
			name: "fluent-bit", namespace: ns.logging,
			ingress: denyAllIngress,
			egress:  []interface{}{apiServerEgress(), dnsEgress(), s3Egress()},
		},
	}
}

func newPolicies(ctx *pulumi.Context, ns *namespaces, opt pulumi.ResourceOption) error {
	for _, p := range policies(ns) {
		if _, err := apiextensions.NewCustomResource(ctx, "cnp-"+p.name, &apiextensions.CustomResourceArgs{
			ApiVersion: pulumi.String("cilium.io/v2"),
			Kind:       pulumi.String("CiliumNetworkPolicy"),
			Metadata:   &metav1.ObjectMetaArgs{Name: pulumi.String("default-deny-" + p.name), Namespace: p.namespace},
			OtherFields: kubernetes.UntypedArgs{
				"spec": obj{
					"endpointSelector": obj{},
					"ingress":          p.ingress,
					"egress":           p.egress,
				},
			},
		}, opt); err != nil {
			return err
		}
	}
	return nil
}
