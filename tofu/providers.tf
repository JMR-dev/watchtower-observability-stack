provider "hcloud" {
  token = var.hcloud_token
}

# AWS provider aliased to Hetzner's S3-compatible Object Storage.
# Used to create the Mimir/Loki/Tempo buckets and lifecycle rules.
provider "aws" {
  alias      = "hetzner"
  region     = var.location
  access_key = var.hetzner_s3_access_key
  secret_key = var.hetzner_s3_secret_key

  endpoints {
    s3 = "https://${var.location}.your-objectstorage.com"
  }

  skip_credentials_validation = true
  skip_region_validation      = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true
}
