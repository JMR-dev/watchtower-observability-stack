package main

import (
	"encoding/base64"
	"strings"

	appsv1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/apps/v1"
	corev1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/core/v1"
	metav1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/meta/v1"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

// gcpProject owns the Cloud DNS zone Caddy answers DNS-01 challenges in.
const gcpProject = "watchtower-observe"

// newEdge runs the pod peers talk to: wg-easy (wg0 = 10.8.0.1) and Caddy in
// one network namespace, so Caddy is reachable at the tunnel address with no
// forwarding or NAT.
//
// A Deployment with Recreate, not a StatefulSet: a StatefulSet never replaces
// a pod stuck on a dead node, and the whole point of the Floating IP is that
// the pod comes back elsewhere. With 30s node-loss tolerations, a hard node
// failure moves it in about 7 minutes (eviction, then Kubernetes' 6-minute
// force-detach of the volumes); a drain moves it in about one. fipd then
// points the Floating IP at the new node.
func newEdge(ctx *pulumi.Context, cfg *Config, ns *namespaces, opts ...pulumi.ResourceOption) error {
	dns, err := newSecret(ctx, "edge-dns01", ns.edge, map[string]pulumi.StringInput{
		"key.json": cfg.CaddyDNSKey,
	}, opts...)
	if err != nil {
		return err
	}
	wg, err := newSecret(ctx, "edge-wg-easy", ns.edge, map[string]pulumi.StringInput{
		"INIT_PASSWORD": cfg.WGEasyPassword,
	}, opts...)
	if err != nil {
		return err
	}
	pull, err := newPullSecret(ctx, cfg, "edge-registry", cfg.CaddyImage, ns.edge, opts...)
	if err != nil {
		return err
	}

	caddyfile := file("Caddyfile")
	cm, err := corev1.NewConfigMap(ctx, "edge-caddyfile", &corev1.ConfigMapArgs{
		Metadata: meta("edge-caddyfile", ns.edge, names.EdgeAppLabel),
		Data:     pulumi.StringMap{"Caddyfile": pulumi.String(caddyfile)},
	}, opts...)
	if err != nil {
		return err
	}

	// Two volumes rather than one with subPaths: a subPath directory the
	// kubelet creates is owned by root, which Caddy (UID 1000) could not
	// write. 10Gi is Hetzner's smallest volume.
	wgData, err := edgeVolume(ctx, "edge-wireguard", ns, opts...)
	if err != nil {
		return err
	}
	caddyData, err := edgeVolume(ctx, "edge-caddy", ns, opts...)
	if err != nil {
		return err
	}

	_, err = appsv1.NewDeployment(ctx, "edge", &appsv1.DeploymentArgs{
		Metadata: meta("edge", ns.edge, names.EdgeAppLabel),
		Spec: &appsv1.DeploymentSpecArgs{
			Replicas: pulumi.Int(1),
			Strategy: &appsv1.DeploymentStrategyArgs{Type: pulumi.String("Recreate")},
			Selector: selector(names.EdgeAppLabel),
			Template: &corev1.PodTemplateSpecArgs{
				Metadata: &metav1.ObjectMetaArgs{
					Labels:      appLabels(names.EdgeAppLabel),
					Annotations: pulumi.StringMap{"checksum/caddyfile": pulumi.String(checksum(caddyfile))},
				},
				Spec: &corev1.PodSpecArgs{
					Tolerations:                  tolerateNodeLoss(),
					ImagePullSecrets:             corev1.LocalObjectReferenceArray{&corev1.LocalObjectReferenceArgs{Name: pull.Metadata.Name()}},
					AutomountServiceAccountToken: pulumi.Bool(false),
					SecurityContext: &corev1.PodSecurityContextArgs{
						SeccompProfile: &corev1.SeccompProfileArgs{Type: pulumi.String("RuntimeDefault")},
						FsGroup:        pulumi.Int(1000),
						// Caddy binds 443 as UID 1000 without NET_BIND_SERVICE.
						// Safe sysctl: it is scoped to the pod's own netns.
						Sysctls: corev1.SysctlArray{&corev1.SysctlArgs{
							Name: pulumi.String("net.ipv4.ip_unprivileged_port_start"), Value: pulumi.String("443"),
						}},
					},
					Containers: corev1.ContainerArray{wgEasyContainer(wg), caddyContainer(cfg, dns)},
					Volumes: corev1.VolumeArray{
						&corev1.VolumeArgs{
							Name:                  pulumi.String("wireguard"),
							PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSourceArgs{ClaimName: wgData.Metadata.Name().Elem()},
						},
						&corev1.VolumeArgs{
							Name:                  pulumi.String("caddy-data"),
							PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSourceArgs{ClaimName: caddyData.Metadata.Name().Elem()},
						},
						&corev1.VolumeArgs{
							Name:      pulumi.String("caddyfile"),
							ConfigMap: &corev1.ConfigMapVolumeSourceArgs{Name: cm.Metadata.Name()},
						},
						&corev1.VolumeArgs{
							Name:   pulumi.String("dns01"),
							Secret: &corev1.SecretVolumeSourceArgs{SecretName: dns.Metadata.Name()},
						},
						&corev1.VolumeArgs{Name: pulumi.String("caddy-config"), EmptyDir: &corev1.EmptyDirVolumeSourceArgs{}},
						&corev1.VolumeArgs{Name: pulumi.String("caddy-tmp"), EmptyDir: &corev1.EmptyDirVolumeSourceArgs{
							SizeLimit: pulumi.String("1Gi"),
						}},
					},
				},
			},
		},
	}, opts...)
	return err
}

// wgEasyContainer owns wg0. NET_ADMIN to create it and set its firewall
// hooks; spc_t because SELinux denies container_t netlink interface
// creation. The wireguard module is loaded on every node by Ansible, so no
// SYS_MODULE and no /lib/modules mount.
func wgEasyContainer(secret *corev1.Secret) *corev1.ContainerArgs {
	env := func(k, v string) *corev1.EnvVarArgs {
		return &corev1.EnvVarArgs{Name: pulumi.String(k), Value: pulumi.String(v)}
	}
	return &corev1.ContainerArgs{
		Name:  pulumi.String("wg-easy"),
		Image: pulumi.String(imageWGEasy),
		Env: corev1.EnvVarArray{
			// Unattended first-start setup; ignored once the DB exists.
			env("INIT_ENABLED", "true"),
			env("INIT_USERNAME", "admin"),
			env("INIT_HOST", names.VPNHost),
			env("INIT_PORT", "51820"),
			env("INIT_DNS", "1.1.1.1,1.0.0.1"),
			env("INIT_IPV4_CIDR", names.TunnelCIDR),
			// Required together with the IPv4 range; unused (DISABLE_IPV6).
			env("INIT_IPV6_CIDR", "fdcc:ad94:bacf:61a3::/64"),
			// Split tunnel: peers send only the tunnel range through wg0, so
			// the pod never forwards traffic anywhere.
			env("INIT_ALLOWED_IPS", names.TunnelCIDR),
			env("DISABLE_IPV6", "true"),
			// The UI stays on loopback; Caddy fronts it with TLS on 51821.
			env("HOST", "127.0.0.1"),
			env("PORT", "51822"),
			env("TRUSTED_PROXIES", "127.0.0.1"),
			env("DISABLE_VERSION_CHECK", "true"),
		},
		EnvFrom: corev1.EnvFromSourceArray{&corev1.EnvFromSourceArgs{
			SecretRef: &corev1.SecretEnvSourceArgs{Name: secret.Metadata.Name()},
		}},
		Ports: corev1.ContainerPortArray{&corev1.ContainerPortArgs{
			Name:          pulumi.String("wireguard"),
			ContainerPort: pulumi.Int(names.PortWireGuard),
			HostPort:      pulumi.Int(names.PortWireGuard),
			Protocol:      pulumi.String("UDP"),
		}},
		SecurityContext: &corev1.SecurityContextArgs{
			AllowPrivilegeEscalation: pulumi.Bool(false),
			Capabilities: &corev1.CapabilitiesArgs{
				Drop: pulumi.StringArray{pulumi.String("ALL")},
				Add:  pulumi.StringArray{pulumi.String("NET_ADMIN"), pulumi.String("NET_RAW")},
			},
			SeLinuxOptions: &corev1.SELinuxOptionsArgs{Type: pulumi.String("spc_t")},
		},
		// Node peaks at about 320 MB resident while starting (measured on
		// k3s); 256Mi got it OOM-killed on every start.
		Resources: &corev1.ResourceRequirementsArgs{
			Requests: pulumi.StringMap{"cpu": pulumi.String("50m"), "memory": pulumi.String("256Mi")},
			Limits:   pulumi.StringMap{"memory": pulumi.String("512Mi")},
		},
		VolumeMounts: corev1.VolumeMountArray{&corev1.VolumeMountArgs{
			Name: pulumi.String("wireguard"), MountPath: pulumi.String("/etc/wireguard"),
		}},
	}
}

// caddyContainer terminates TLS on the tunnel address and proxies to the
// backends. Unprivileged, container_t, read-only root.
func caddyContainer(cfg *Config, dns *corev1.Secret) *corev1.ContainerArgs {
	env := func(k, v string) *corev1.EnvVarArgs {
		return &corev1.EnvVarArgs{Name: pulumi.String(k), Value: pulumi.String(v)}
	}
	var ports corev1.ContainerPortArray
	for _, p := range []int{names.PortGrafana, names.PortLoki, names.PortMimir, names.PortTempo, names.PortOTLPGRPC, names.PortOTLPHTTP, names.PortWGUI} {
		ports = append(ports, &corev1.ContainerPortArgs{ContainerPort: pulumi.Int(p)})
	}
	sc := restricted()
	sc.RunAsUser = pulumi.Int(1000)
	sc.RunAsGroup = pulumi.Int(1000)
	return &corev1.ContainerArgs{
		Name:  pulumi.String("caddy"),
		Image: pulumi.String(cfg.CaddyImage),
		Env: corev1.EnvVarArray{
			env("DOMAIN", names.Domain),
			env("GCP_PROJECT", gcpProject),
			env("GOOGLE_APPLICATION_CREDENTIALS", "/etc/caddy-dns/key.json"),
			env("XDG_CONFIG_HOME", "/config"),
		},
		Ports:           ports,
		SecurityContext: sc,
		ReadinessProbe: &corev1.ProbeArgs{
			TcpSocket:           &corev1.TCPSocketActionArgs{Port: pulumi.Int(names.PortLoki)},
			InitialDelaySeconds: pulumi.Int(5),
		},
		Resources: &corev1.ResourceRequirementsArgs{
			Requests: pulumi.StringMap{"cpu": pulumi.String("100m"), "memory": pulumi.String("256Mi")},
			Limits:   pulumi.StringMap{"memory": pulumi.String("768Mi")},
		},
		VolumeMounts: corev1.VolumeMountArray{
			&corev1.VolumeMountArgs{Name: pulumi.String("caddyfile"), MountPath: pulumi.String("/etc/caddy"), ReadOnly: pulumi.Bool(true)},
			&corev1.VolumeMountArgs{Name: pulumi.String("dns01"), MountPath: pulumi.String("/etc/caddy-dns"), ReadOnly: pulumi.Bool(true)},
			&corev1.VolumeMountArgs{Name: pulumi.String("caddy-data"), MountPath: pulumi.String("/data")},
			&corev1.VolumeMountArgs{Name: pulumi.String("caddy-config"), MountPath: pulumi.String("/config")},
			// Coraza refuses to start unless it can create a file in the temp
			// dir, and buffers large request bodies there.
			&corev1.VolumeMountArgs{Name: pulumi.String("caddy-tmp"), MountPath: pulumi.String("/tmp")},
		},
	}
}

// edgeVolume is one of the edge pod's protected volumes: wg-easy's database
// (every peer's keys) and Caddy's certificates and ACME account.
func edgeVolume(ctx *pulumi.Context, name string, ns *namespaces, opts ...pulumi.ResourceOption) (*corev1.PersistentVolumeClaim, error) {
	return corev1.NewPersistentVolumeClaim(ctx, name, &corev1.PersistentVolumeClaimArgs{
		Metadata: meta(name, ns.edge, names.EdgeAppLabel),
		Spec: &corev1.PersistentVolumeClaimSpecArgs{
			AccessModes:      pulumi.StringArray{pulumi.String("ReadWriteOnce")},
			StorageClassName: pulumi.String(storageClass),
			Resources: &corev1.VolumeResourceRequirementsArgs{
				Requests: pulumi.StringMap{"storage": pulumi.String("10Gi")},
			},
		},
	}, append(opts, pulumi.Protect(true))...)
}

// newPullSecret is a dockerconfigjson Secret for the Gitea registry that
// image lives in, with a read-only package token.
func newPullSecret(ctx *pulumi.Context, cfg *Config, name, image string, namespace pulumi.StringInput,
	opts ...pulumi.ResourceOption,
) (*corev1.Secret, error) {
	host := strings.SplitN(image, "/", 2)[0]
	dockerConfig := cfg.RegistryToken.ApplyT(func(token string) (string, error) {
		auth := base64.StdEncoding.EncodeToString([]byte(cfg.RegistryUser + ":" + token))
		b, err := marshalJSON(obj{"auths": obj{host: obj{
			"username": cfg.RegistryUser, "password": token, "auth": auth,
		}}})
		return string(b), err
	}).(pulumi.StringOutput)
	return corev1.NewSecret(ctx, name, &corev1.SecretArgs{
		Metadata:   meta(name, namespace, name),
		Type:       pulumi.String("kubernetes.io/dockerconfigjson"),
		StringData: pulumi.StringMap{".dockerconfigjson": pulumi.ToSecret(dockerConfig).(pulumi.StringOutput)},
	}, opts...)
}
