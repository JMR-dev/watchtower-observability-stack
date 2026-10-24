package main

import (
	"fmt"

	appsv1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/apps/v1"
	corev1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/core/v1"
	metav1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/meta/v1"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

// mimirConfig is Mimir's monolithic config, ported from mimir.yaml.j2. The
// mimir-distributed chart is not used: its 3.x releases hard-wire the Kafka
// ingest-storage architecture, and one process (with the classic
// architecture, still supported in 3.x) is plenty for this metrics volume.
//
// S3 credentials come from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY: with no
// keys in the config, Mimir's S3 client reads the environment.
func mimirConfig(cfg *Config) obj {
	s3 := func(bucket string) obj {
		return obj{
			"endpoint":    names.S3Endpoint,
			"region":      names.S3Region,
			"bucket_name": bucket,
			"insecure":    false,
		}
	}
	memberlist := obj{"store": "memberlist"}
	return obj{
		"target":               "all,alertmanager,overrides-exporter",
		"multitenancy_enabled": true,
		"activity_tracker":     obj{"filepath": "/data/metrics-activity.log"},
		"server":               obj{"http_listen_port": names.PortMimir, "grpc_listen_port": 9095, "log_level": "info"},
		"ingest_storage":       obj{"enabled": false},
		"blocks_storage": obj{
			"backend": "s3",
			"s3":      s3(cfg.bucket("mimir-blocks")),
			"tsdb":    obj{"dir": "/data/tsdb", "retention_period": "24h"},
			"bucket_store": obj{
				"sync_dir": "/data/tsdb-sync",
			},
		},
		"ruler_storage":        obj{"backend": "s3", "s3": s3(cfg.bucket("mimir-ruler"))},
		"alertmanager_storage": obj{"backend": "s3", "s3": s3(cfg.bucket("mimir-alertmanager"))},
		"compactor": obj{
			"data_dir":      "/data/compactor",
			"sharding_ring": obj{"kvstore": memberlist},
		},
		"distributor": obj{"ring": obj{"instance_addr": "127.0.0.1", "kvstore": memberlist}},
		"ingester": obj{"ring": obj{
			"instance_addr":      "127.0.0.1",
			"kvstore":            memberlist,
			"replication_factor": 1,
		}},
		"ruler": obj{
			"rule_path":        "/data/rules",
			"alertmanager_url": fmt.Sprintf("http://localhost:%d/alertmanager", names.PortMimir),
			"ring":             obj{"instance_addr": "127.0.0.1"},
		},
		"alertmanager": obj{
			"data_dir":      "/data/alertmanager",
			"external_url":  fmt.Sprintf("https://%s:%d/alertmanager", names.Domain, names.PortMimir),
			"sharding_ring": obj{"replication_factor": 1},
		},
		"store_gateway": obj{"sharding_ring": obj{"replication_factor": 1}},
		"memberlist":    obj{"bind_port": 7946},
		"limits": obj{
			"compactor_blocks_retention_period": fmt.Sprintf("%dd", names.RetentionMimirDays),
			"ingestion_rate":                    100000,
			"ingestion_burst_size":              1000000,
			"max_global_series_per_user":        500000,
			"max_label_names_per_series":        30,
		},
		"runtime_config": obj{"file": "/etc/mimir/runtime.yaml"},
		"usage_stats":    obj{"enabled": false},
	}
}

// newMimir runs Mimir as a one-replica StatefulSet. A singleton on purpose,
// for cost: during its node's reboot, remote_write clients get a few minutes
// of 5xx and retry. No PDB, since one would block every drain.
func newMimir(ctx *pulumi.Context, cfg *Config, ns *namespaces, opts ...pulumi.ResourceOption) error {
	secret, err := s3Secret(ctx, cfg, "mimir-s3", names.KeyMimir, ns.apps, opts...)
	if err != nil {
		return err
	}
	rendered, err := marshalYAML(mimirConfig(cfg))
	if err != nil {
		return err
	}
	config := string(rendered)
	cm, err := corev1.NewConfigMap(ctx, "mimir-config", &corev1.ConfigMapArgs{
		Metadata: meta("mimir-config", ns.apps, "mimir"),
		Data: pulumi.StringMap{
			"mimir.yaml": pulumi.String(config),
			// Hot-reloaded per-tenant overrides; empty by default.
			"runtime.yaml": pulumi.String("overrides: {}\n"),
		},
	}, opts...)
	if err != nil {
		return err
	}

	if _, err := corev1.NewService(ctx, "mimir", &corev1.ServiceArgs{
		Metadata: meta("mimir", ns.apps, "mimir"),
		Spec: &corev1.ServiceSpecArgs{
			Selector: pulumi.StringMap{"app.kubernetes.io/name": pulumi.String("mimir")},
			Ports: corev1.ServicePortArray{
				&corev1.ServicePortArgs{Name: pulumi.String("http"), Port: pulumi.Int(names.PortMimir), TargetPort: pulumi.String("http")},
				&corev1.ServicePortArgs{Name: pulumi.String("grpc"), Port: pulumi.Int(9095), TargetPort: pulumi.String("grpc")},
			},
		},
	}, opts...); err != nil {
		return err
	}

	_, err = appsv1.NewStatefulSet(ctx, "mimir", &appsv1.StatefulSetArgs{
		Metadata: meta("mimir", ns.apps, "mimir"),
		Spec: &appsv1.StatefulSetSpecArgs{
			ServiceName: pulumi.String("mimir"),
			Replicas:    pulumi.Int(1),
			Selector:    selector("mimir"),
			Template: &corev1.PodTemplateSpecArgs{
				Metadata: &metav1.ObjectMetaArgs{
					Labels:      appLabels("mimir"),
					Annotations: pulumi.StringMap{"checksum/config": pulumi.String(checksum(config))},
				},
				Spec: &corev1.PodSpecArgs{
					SecurityContext: &corev1.PodSecurityContextArgs{
						RunAsUser:      pulumi.Int(10001),
						RunAsGroup:     pulumi.Int(10001),
						FsGroup:        pulumi.Int(10001),
						RunAsNonRoot:   pulumi.Bool(true),
						SeccompProfile: &corev1.SeccompProfileArgs{Type: pulumi.String("RuntimeDefault")},
					},
					TerminationGracePeriodSeconds: pulumi.Int(300),
					Containers: corev1.ContainerArray{&corev1.ContainerArgs{
						Name:  pulumi.String("mimir"),
						Image: pulumi.String(imageMimir),
						Args: pulumi.StringArray{
							pulumi.String("-config.file=/etc/mimir/mimir.yaml"),
						},
						EnvFrom: corev1.EnvFromSourceArray{&corev1.EnvFromSourceArgs{
							SecretRef: &corev1.SecretEnvSourceArgs{Name: secret.Metadata.Name()},
						}},
						Ports: corev1.ContainerPortArray{
							&corev1.ContainerPortArgs{Name: pulumi.String("http"), ContainerPort: pulumi.Int(names.PortMimir)},
							&corev1.ContainerPortArgs{Name: pulumi.String("grpc"), ContainerPort: pulumi.Int(9095)},
							&corev1.ContainerPortArgs{Name: pulumi.String("memberlist"), ContainerPort: pulumi.Int(7946)},
						},
						ReadinessProbe: &corev1.ProbeArgs{
							HttpGet:             &corev1.HTTPGetActionArgs{Path: pulumi.String("/ready"), Port: pulumi.String("http")},
							InitialDelaySeconds: pulumi.Int(45),
						},
						Resources: &corev1.ResourceRequirementsArgs{
							Requests: pulumi.StringMap{"cpu": pulumi.String("500m"), "memory": pulumi.String("2Gi")},
							Limits:   pulumi.StringMap{"memory": pulumi.String("6Gi")},
						},
						SecurityContext: restricted(),
						VolumeMounts: corev1.VolumeMountArray{
							&corev1.VolumeMountArgs{Name: pulumi.String("config"), MountPath: pulumi.String("/etc/mimir")},
							&corev1.VolumeMountArgs{Name: pulumi.String("data"), MountPath: pulumi.String("/data")},
						},
					}},
					Volumes: corev1.VolumeArray{&corev1.VolumeArgs{
						Name:      pulumi.String("config"),
						ConfigMap: &corev1.ConfigMapVolumeSourceArgs{Name: cm.Metadata.Name()},
					}},
				},
			},
			VolumeClaimTemplates: corev1.PersistentVolumeClaimTypeArray{&corev1.PersistentVolumeClaimTypeArgs{
				Metadata: &metav1.ObjectMetaArgs{Name: pulumi.String("data")},
				Spec: &corev1.PersistentVolumeClaimSpecArgs{
					AccessModes:      pulumi.StringArray{pulumi.String("ReadWriteOnce")},
					StorageClassName: pulumi.String(storageClass),
					Resources: &corev1.VolumeResourceRequirementsArgs{
						Requests: pulumi.StringMap{"storage": pulumi.String("50Gi")},
					},
				},
			}},
		},
	}, opts...)
	return err
}

// storageClass is hcloud-csi's LUKS-encrypted class (values/hcloud-csi.yaml).
const storageClass = "hcloud-luks"
