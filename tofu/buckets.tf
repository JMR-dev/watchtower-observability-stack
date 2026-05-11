locals {
  buckets = {
    mimir = { name = "${var.bucket_prefix}-mimir" }
    loki  = { name = "${var.bucket_prefix}-loki" }
    tempo = { name = "${var.bucket_prefix}-tempo" }
  }
}

resource "aws_s3_bucket" "telemetry" {
  for_each = local.buckets
  provider = aws.hetzner

  bucket = each.value.name

  # Hetzner does not yet support all S3 ACL operations, so keep this minimal.
  # Note: Hetzner Object Storage does not support the S3 Lifecycle Configuration
  # API (PutBucketLifecycleConfiguration / GetBucketLifecycleConfiguration).
  # Retention is enforced at the application layer: Mimir, Loki, and Tempo each
  # have native retention settings configured via their respective config files.
  lifecycle {
    prevent_destroy = true
  }
}
