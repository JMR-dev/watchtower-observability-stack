package main

import (
	appsv1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/apps/v1"
	corev1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/core/v1"
	metav1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/meta/v1"
	rbacv1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/rbac/v1"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

// newLogship runs Fluent Bit on every node (files/fluent-bit.conf): every
// container's log, the node's journal and the API server audit log go to
// the log-archive bucket, which expires objects after 90 days. Its S3 key
// can only write: a compromised node cannot read back or erase the archive.
func newLogship(ctx *pulumi.Context, cfg *Config, ns *namespaces, opts ...pulumi.ResourceOption) error {
	secret, err := s3Secret(ctx, cfg, "logship-s3", names.KeyLogship, ns.logging, opts...)
	if err != nil {
		return err
	}
	conf := file("fluent-bit.conf")
	cm, err := corev1.NewConfigMap(ctx, "fluent-bit", &corev1.ConfigMapArgs{
		Metadata: meta("fluent-bit", ns.logging, "fluent-bit"),
		Data:     pulumi.StringMap{"fluent-bit.conf": pulumi.String(conf)},
	}, opts...)
	if err != nil {
		return err
	}
	sa, err := corev1.NewServiceAccount(ctx, "fluent-bit", &corev1.ServiceAccountArgs{
		Metadata: meta("fluent-bit", ns.logging, "fluent-bit"),
	}, opts...)
	if err != nil {
		return err
	}
	// The kubernetes filter adds pod, namespace and label metadata.
	role, err := rbacv1.NewClusterRole(ctx, "fluent-bit", &rbacv1.ClusterRoleArgs{
		Metadata: &metav1.ObjectMetaArgs{Name: pulumi.String("fluent-bit"), Labels: appLabels("fluent-bit")},
		Rules: rbacv1.PolicyRuleArray{&rbacv1.PolicyRuleArgs{
			ApiGroups: pulumi.StringArray{pulumi.String("")},
			Resources: pulumi.ToStringArray([]string{"pods", "namespaces"}),
			Verbs:     pulumi.ToStringArray([]string{"get", "list", "watch"}),
		}},
	}, opts...)
	if err != nil {
		return err
	}
	if _, err := rbacv1.NewClusterRoleBinding(ctx, "fluent-bit", &rbacv1.ClusterRoleBindingArgs{
		Metadata: &metav1.ObjectMetaArgs{Name: pulumi.String("fluent-bit"), Labels: appLabels("fluent-bit")},
		RoleRef: &rbacv1.RoleRefArgs{
			ApiGroup: pulumi.String("rbac.authorization.k8s.io"), Kind: pulumi.String("ClusterRole"), Name: role.Metadata.Name().Elem(),
		},
		Subjects: rbacv1.SubjectArray{&rbacv1.SubjectArgs{
			Kind: pulumi.String("ServiceAccount"), Name: sa.Metadata.Name().Elem(), Namespace: ns.logging,
		}},
	}, opts...); err != nil {
		return err
	}

	env := func(k, v string) *corev1.EnvVarArgs {
		return &corev1.EnvVarArgs{Name: pulumi.String(k), Value: pulumi.String(v)}
	}
	hostPath := func(name, path, kind string) *corev1.VolumeArgs {
		return &corev1.VolumeArgs{
			Name:     pulumi.String(name),
			HostPath: &corev1.HostPathVolumeSourceArgs{Path: pulumi.String(path), Type: pulumi.String(kind)},
		}
	}
	mount := func(name, path string, ro bool) *corev1.VolumeMountArgs {
		return &corev1.VolumeMountArgs{Name: pulumi.String(name), MountPath: pulumi.String(path), ReadOnly: pulumi.Bool(ro)}
	}

	_, err = appsv1.NewDaemonSet(ctx, "fluent-bit", &appsv1.DaemonSetArgs{
		Metadata: meta("fluent-bit", ns.logging, "fluent-bit"),
		Spec: &appsv1.DaemonSetSpecArgs{
			Selector: selector("fluent-bit"),
			Template: &corev1.PodTemplateSpecArgs{
				Metadata: &metav1.ObjectMetaArgs{
					Labels:      appLabels("fluent-bit"),
					Annotations: pulumi.StringMap{"checksum/config": pulumi.String(checksum(conf))},
				},
				Spec: &corev1.PodSpecArgs{
					ServiceAccountName: sa.Metadata.Name(),
					PriorityClassName:  pulumi.String("system-node-critical"),
					// Every node, whatever its taints: a log archive with
					// gaps is not an archive.
					Tolerations: corev1.TolerationArray{&corev1.TolerationArgs{Operator: pulumi.String("Exists")}},
					SecurityContext: &corev1.PodSecurityContextArgs{
						SeccompProfile: &corev1.SeccompProfileArgs{Type: pulumi.String("RuntimeDefault")},
					},
					Containers: corev1.ContainerArray{&corev1.ContainerArgs{
						Name:  pulumi.String("fluent-bit"),
						Image: pulumi.String(imageFluentBit),
						Args:  pulumi.StringArray{pulumi.String("--config=/fluent-bit/etc/conf/fluent-bit.conf")},
						Env: corev1.EnvVarArray{
							env("S3_BUCKET", cfg.bucket("logs-archive")),
							env("S3_REGION", names.S3Region),
							env("S3_ENDPOINT", names.S3Endpoint),
							&corev1.EnvVarArgs{
								Name: pulumi.String("NODE_NAME"),
								ValueFrom: &corev1.EnvVarSourceArgs{
									FieldRef: &corev1.ObjectFieldSelectorArgs{FieldPath: pulumi.String("spec.nodeName")},
								},
							},
						},
						EnvFrom: corev1.EnvFromSourceArray{&corev1.EnvFromSourceArgs{
							SecretRef: &corev1.SecretEnvSourceArgs{Name: secret.Metadata.Name()},
						}},
						Ports: corev1.ContainerPortArray{&corev1.ContainerPortArgs{
							Name: pulumi.String("http"), ContainerPort: pulumi.Int(2020),
						}},
						LivenessProbe: &corev1.ProbeArgs{
							HttpGet: &corev1.HTTPGetActionArgs{Path: pulumi.String("/api/v1/health"), Port: pulumi.String("http")},
						},
						Resources: &corev1.ResourceRequirementsArgs{
							Requests: pulumi.StringMap{"cpu": pulumi.String("50m"), "memory": pulumi.String("64Mi")},
							Limits:   pulumi.StringMap{"memory": pulumi.String("256Mi")},
						},
						// Root to read root-owned host logs, but with every
						// capability dropped and a read-only root. spc_t
						// because container_t cannot read host log paths
						// under SELinux enforcing.
						SecurityContext: &corev1.SecurityContextArgs{
							RunAsUser:                pulumi.Int(0),
							AllowPrivilegeEscalation: pulumi.Bool(false),
							ReadOnlyRootFilesystem:   pulumi.Bool(true),
							Capabilities:             &corev1.CapabilitiesArgs{Drop: pulumi.StringArray{pulumi.String("ALL")}},
							SeLinuxOptions:           &corev1.SELinuxOptionsArgs{Type: pulumi.String("spc_t")},
						},
						VolumeMounts: corev1.VolumeMountArray{
							mount("config", "/fluent-bit/etc/conf", true),
							mount("varlog", "/var/log", true),
							mount("machine-id", "/etc/machine-id", true),
							mount("state", "/var/lib/fluent-bit", false),
						},
					}},
					Volumes: corev1.VolumeArray{
						&corev1.VolumeArgs{
							Name:      pulumi.String("config"),
							ConfigMap: &corev1.ConfigMapVolumeSourceArgs{Name: cm.Metadata.Name()},
						},
						hostPath("varlog", "/var/log", "Directory"),
						hostPath("machine-id", "/etc/machine-id", "File"),
						// Buffer and read positions survive restarts, so a
						// redeploy neither drops nor re-sends logs.
						hostPath("state", "/var/lib/fluent-bit", "DirectoryOrCreate"),
					},
				},
			},
		},
	}, opts...)
	return err
}
