locals {
  buckets = {
    mimir = {
      name           = "${var.bucket_prefix}-mimir"
      retention_days = 365
    }
    loki = {
      name           = "${var.bucket_prefix}-loki"
      retention_days = 90
    }
    tempo = {
      name           = "${var.bucket_prefix}-tempo"
      retention_days = 30
    }
  }
}

resource "aws_s3_bucket" "telemetry" {
  for_each = local.buckets
  provider = aws.hetzner

  bucket = each.value.name

  # Hetzner does not yet support all S3 ACL operations, so keep this minimal.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "telemetry" {
  for_each = local.buckets
  provider = aws.hetzner

  bucket = aws_s3_bucket.telemetry[each.key].id
  versioning_configuration {
    status = "Suspended"
  }
}

# Lifecycle rule: hard-delete safety net behind application retention.
resource "aws_s3_bucket_lifecycle_configuration" "telemetry" {
  for_each = local.buckets
  provider = aws.hetzner

  bucket = aws_s3_bucket.telemetry[each.key].id

  rule {
    id     = "hard-delete-after-${each.value.retention_days}d"
    status = "Enabled"

    filter {}

    expiration {
      days = each.value.retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
