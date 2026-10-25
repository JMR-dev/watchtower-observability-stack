package main

import (
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-minio/sdk/go/minio"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/names"
)

// Buckets go through the MinIO provider because that is the IaC path
// Hetzner documents for its Object Storage; the AWS provider's lifecycle
// resource sends AWS-only fields Hetzner has not been shown to accept. Only
// this file knows which provider it is.

// writeOnlyDenied is what a write-only key may not do. Hetzner accepts
// NotAction in a policy but ignores it, so "everything but PutObject" has to
// be spelled out as a deny list.
//
// The list holds only because both writers upload with a single PutObject
// (Fluent Bit's use_put_object, the Postgres backup's curl -T): a multipart
// upload would also need CreateMultipartUpload, UploadPart and
// CompleteMultipartUpload.
//
// Reads are one wildcard, s3:GetObject*, which also covers the variants
// listed nowhere here. Hetzner answers 503 to a policy naming an action it
// doesn't know, such as s3:GetObjectAttributes; the wildcard it accepts and
// enforces (checked on 2026-10-25: the cluster key could put, but not get,
// head, list or delete).
var writeOnlyDenied = []string{
	"s3:GetObject*",
	"s3:DeleteObject",
	"s3:DeleteObjectVersion",
	"s3:ListBucket",
	"s3:ListBucketVersions",
	"s3:ListBucketMultipartUploads",
	"s3:GetBucketPolicy",
	"s3:PutBucketPolicy",
	"s3:DeleteBucketPolicy",
	"s3:GetLifecycleConfiguration",
	"s3:PutLifecycleConfiguration",
	"s3:PutBucketVersioning",
	"s3:PutBucketObjectLockConfiguration",
	"s3:PutObjectRetention",
	"s3:PutObjectLegalHold",
	"s3:DeleteBucket",
}

type policyDoc struct {
	Version   string      `json:"Version"`
	Statement []statement `json:"Statement"`
}

type statement struct {
	Sid          string      `json:"Sid"`
	Effect       string      `json:"Effect"`
	Action       interface{} `json:"Action"`
	Resource     []string    `json:"Resource"`
	Principal    *principals `json:"Principal,omitempty"`
	NotPrincipal *principals `json:"NotPrincipal,omitempty"`
}

type principals struct {
	AWS []string `json:"AWS"`
}

// principal is Hetzner's IAM-style user for one access key in one project.
func principal(projectID int, accessKey string) string {
	return fmt.Sprintf("arn:aws:iam:::user/p%d:%s", projectID, accessKey)
}

// bucketPolicy keeps every key out of bucket except the admin key and the
// bucket's own component key, and makes the component key write-only where
// the bucket says so. Every key is project-wide by default, so this is what
// stops, say, Loki's key from reading the log archive.
func bucketPolicy(cfg *Config, bucket string, b names.Bucket) (string, error) {
	resources := []string{"arn:aws:s3:::" + bucket, "arn:aws:s3:::" + bucket + "/*"}
	admin := principal(cfg.HetznerProjectID, cfg.S3AccessKeys[names.KeyAdmin])
	owner := principal(cfg.HetznerProjectID, cfg.S3AccessKeys[b.Key])
	doc := policyDoc{
		Version: "2012-10-17",
		Statement: []statement{{
			Sid:          "OnlyAdminAndOwner",
			Effect:       "Deny",
			Action:       "s3:*",
			Resource:     resources,
			NotPrincipal: &principals{AWS: []string{admin, owner}},
		}},
	}
	if b.WriteOnly {
		doc.Statement = append(doc.Statement, statement{
			Sid:       "OwnerWritesOnly",
			Effect:    "Deny",
			Action:    writeOnlyDenied,
			Resource:  resources,
			Principal: &principals{AWS: []string{owner}},
		})
	}
	if b.Suffix == names.BucketLogArchive {
		doc.Statement = append(doc.Statement, statement{
			// PutObject can overwrite; keep the shipper away from the
			// erasure records.
			Sid:       "OwnerLeavesGDPRRecords",
			Effect:    "Deny",
			Action:    "s3:PutObject",
			Resource:  []string{"arn:aws:s3:::" + bucket + "/" + names.ArchivePrefixGDPR + "*"},
			Principal: &principals{AWS: []string{owner}},
		})
	}
	out, err := marshalJSON(doc)
	return string(out), err
}

// newBuckets creates every names.Buckets entry, protected: deleting one
// deletes that signal's history.
func newBuckets(ctx *pulumi.Context, cfg *Config, p *providers) (pulumi.StringMap, error) {
	opt := pulumi.Provider(p.s3)
	out := pulumi.StringMap{}
	for _, b := range names.Buckets {
		name := names.BucketName(cfg.BucketPrefix, b.Suffix)
		bucket, err := minio.NewS3Bucket(ctx, name, &minio.S3BucketArgs{
			Bucket: pulumi.String(name),
			Acl:    pulumi.String("private"),
		}, opt, pulumi.Protect(true))
		if err != nil {
			return nil, err
		}

		policy, err := bucketPolicy(cfg, name, b)
		if err != nil {
			return nil, err
		}
		// The policy names access key IDs; the repo is mirrored publicly.
		if _, err := minio.NewS3BucketPolicy(ctx, name+"-policy", &minio.S3BucketPolicyArgs{
			Bucket: bucket.Bucket,
			Policy: pulumi.ToSecret(pulumi.String(policy)).(pulumi.StringOutput),
		}, opt); err != nil {
			return nil, err
		}

		if b.LifecycleDays > 0 {
			if _, err := minio.NewIlmPolicy(ctx, name+"-lifecycle", &minio.IlmPolicyArgs{
				Bucket: bucket.Bucket,
				Rules:  lifecycleRules(b),
			}, opt); err != nil {
				return nil, err
			}
		}
		out[b.Suffix] = bucket.Bucket
	}
	return out, nil
}

// lifecycleRules expires the whole bucket, or only the listed prefixes. A
// rule's status is the provider's to set (always Enabled); it refuses one
// given here.
func lifecycleRules(b names.Bucket) minio.IlmPolicyRuleArray {
	expiration := pulumi.String(fmt.Sprintf("%dd", b.LifecycleDays))
	if len(b.LifecyclePrefixes) == 0 {
		return minio.IlmPolicyRuleArray{&minio.IlmPolicyRuleArgs{
			Id: pulumi.String("expire"), Expiration: expiration,
		}}
	}
	var rules minio.IlmPolicyRuleArray
	for _, prefix := range b.LifecyclePrefixes {
		rules = append(rules, &minio.IlmPolicyRuleArgs{
			Id:         pulumi.String("expire-" + strings.TrimSuffix(prefix, "/")),
			Filter:     pulumi.String(prefix),
			Expiration: expiration,
		})
	}
	return rules
}
