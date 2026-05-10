terraform {
  required_version = ">= 1.10.0"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.48"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # State backend: Cloudflare R2 (S3-compatible).
  # Authenticate using AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars
  # set to your Cloudflare R2 access key/secret. Account ID embedded in endpoint.
  #
  # use_lockfile = true requires OpenTofu >= 1.10 and provides native S3-based
  # state locking via conditional PutObject (no DynamoDB needed; R2-compatible).
  backend "s3" {
    bucket = "watchtower-tofu-state"
    key    = "watchtower/terraform.tfstate"
    region = "auto"

    # Cloudflare R2 endpoint (set via -backend-config or env at init):
    #   endpoints = { s3 = "https://<ACCOUNT_ID>.r2.cloudflarestorage.com" }
    # See backend.hcl.example.

    use_lockfile                = true
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_metadata_api_check     = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
    use_path_style              = true
  }
}
