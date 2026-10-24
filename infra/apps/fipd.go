package main

import (
	appsv1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/apps/v1"
	corev1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/core/v1"
	metav1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/meta/v1"
	rbacv1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/rbac/v1"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

// newFipd runs the Floating IP controller (../../fipd). It lives in its own
// restricted namespace with its own Hetzner token, so the internet-facing
// edge pod never holds a Hetzner credential: a project-wide token there would
// turn an edge compromise into control of every server.
func newFipd(ctx *pulumi.Context, cfg *Config, ns *namespaces, opts ...pulumi.ResourceOption) error {
	token, err := newSecret(ctx, "fipd-hcloud", ns.fip, map[string]pulumi.StringInput{
		"HCLOUD_TOKEN": cfg.HcloudFipToken,
	}, opts...)
	if err != nil {
		return err
	}
	pull, err := newPullSecret(ctx, cfg, "fipd-registry", cfg.FipdImage, ns.fip, opts...)
	if err != nil {
		return err
	}
	sa, err := corev1.NewServiceAccount(ctx, "fipd", &corev1.ServiceAccountArgs{
		Metadata: meta("fipd", ns.fip, "fipd"),
	}, opts...)
	if err != nil {
		return err
	}
	subject := rbacv1.SubjectArray{&rbacv1.SubjectArgs{
		Kind: pulumi.String("ServiceAccount"), Name: sa.Metadata.Name().Elem(), Namespace: ns.fip,
	}}

	// Read the edge pods...
	role, err := rbacv1.NewRole(ctx, "fipd-edge-pods", &rbacv1.RoleArgs{
		Metadata: meta("fipd-edge-pods", ns.edge, "fipd"),
		Rules: rbacv1.PolicyRuleArray{&rbacv1.PolicyRuleArgs{
			ApiGroups: pulumi.StringArray{pulumi.String("")},
			Resources: pulumi.StringArray{pulumi.String("pods")},
			Verbs:     pulumi.ToStringArray([]string{"get", "list", "watch"}),
		}},
	}, opts...)
	if err != nil {
		return err
	}
	if _, err := rbacv1.NewRoleBinding(ctx, "fipd-edge-pods", &rbacv1.RoleBindingArgs{
		Metadata: meta("fipd-edge-pods", ns.edge, "fipd"),
		RoleRef: &rbacv1.RoleRefArgs{
			ApiGroup: pulumi.String("rbac.authorization.k8s.io"), Kind: pulumi.String("Role"), Name: role.Metadata.Name().Elem(),
		},
		Subjects: subject,
	}, opts...); err != nil {
		return err
	}

	// ...and the nodes they run on (Ready condition, providerID).
	nodes, err := rbacv1.NewClusterRole(ctx, "fipd-nodes", &rbacv1.ClusterRoleArgs{
		Metadata: &metav1.ObjectMetaArgs{Name: pulumi.String("fipd-nodes"), Labels: appLabels("fipd")},
		Rules: rbacv1.PolicyRuleArray{&rbacv1.PolicyRuleArgs{
			ApiGroups: pulumi.StringArray{pulumi.String("")},
			Resources: pulumi.StringArray{pulumi.String("nodes")},
			Verbs:     pulumi.ToStringArray([]string{"get", "list", "watch"}),
		}},
	}, opts...)
	if err != nil {
		return err
	}
	if _, err := rbacv1.NewClusterRoleBinding(ctx, "fipd-nodes", &rbacv1.ClusterRoleBindingArgs{
		Metadata: &metav1.ObjectMetaArgs{Name: pulumi.String("fipd-nodes"), Labels: appLabels("fipd")},
		RoleRef: &rbacv1.RoleRefArgs{
			ApiGroup: pulumi.String("rbac.authorization.k8s.io"), Kind: pulumi.String("ClusterRole"), Name: nodes.Metadata.Name().Elem(),
		},
		Subjects: subject,
	}, opts...); err != nil {
		return err
	}

	_, err = appsv1.NewDeployment(ctx, "fipd", &appsv1.DeploymentArgs{
		Metadata: meta("fipd", ns.fip, "fipd"),
		Spec: &appsv1.DeploymentSpecArgs{
			Replicas: pulumi.Int(1),
			Selector: selector("fipd"),
			Template: &corev1.PodTemplateSpecArgs{
				Metadata: &metav1.ObjectMetaArgs{Labels: appLabels("fipd")},
				Spec: &corev1.PodSpecArgs{
					ServiceAccountName: sa.Metadata.Name(),
					ImagePullSecrets:   corev1.LocalObjectReferenceArray{&corev1.LocalObjectReferenceArgs{Name: pull.Metadata.Name()}},
					Tolerations:        tolerateNodeLoss(),
					SecurityContext: &corev1.PodSecurityContextArgs{
						RunAsNonRoot:   pulumi.Bool(true),
						RunAsUser:      pulumi.Int(65532),
						SeccompProfile: &corev1.SeccompProfileArgs{Type: pulumi.String("RuntimeDefault")},
					},
					Containers: corev1.ContainerArray{&corev1.ContainerArgs{
						Name:  pulumi.String("fipd"),
						Image: pulumi.String(cfg.FipdImage),
						Args: pulumi.StringArray{
							pulumi.String("--namespace=" + names.NamespaceEdge),
							pulumi.String("--selector=app.kubernetes.io/name=" + names.EdgeAppLabel),
							pulumi.String("--floating-ip-selector=role=" + names.FloatingIPLabel),
							pulumi.String("--interval=10s"),
							pulumi.String("--health-addr=:8081"),
						},
						EnvFrom: corev1.EnvFromSourceArray{&corev1.EnvFromSourceArgs{
							SecretRef: &corev1.SecretEnvSourceArgs{Name: token.Metadata.Name()},
						}},
						Ports: corev1.ContainerPortArray{&corev1.ContainerPortArgs{
							Name: pulumi.String("health"), ContainerPort: pulumi.Int(8081),
						}},
						LivenessProbe: &corev1.ProbeArgs{
							HttpGet:          &corev1.HTTPGetActionArgs{Path: pulumi.String("/healthz"), Port: pulumi.String("health")},
							PeriodSeconds:    pulumi.Int(15),
							FailureThreshold: pulumi.Int(4),
						},
						Resources: &corev1.ResourceRequirementsArgs{
							Requests: pulumi.StringMap{"cpu": pulumi.String("10m"), "memory": pulumi.String("32Mi")},
							Limits:   pulumi.StringMap{"memory": pulumi.String("64Mi")},
						},
						SecurityContext: restricted(),
					}},
				},
			},
		},
	}, opts...)
	return err
}
