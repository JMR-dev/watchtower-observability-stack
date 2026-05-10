variable "hcloud_token" {
  description = "Hetzner Cloud API token (Read & Write)."
  type        = string
  sensitive   = true
}

variable "hetzner_s3_access_key" {
  description = "Hetzner Object Storage access key (created in Cloud Console under Security)."
  type        = string
  sensitive   = true
}

variable "hetzner_s3_secret_key" {
  description = "Hetzner Object Storage secret key."
  type        = string
  sensitive   = true
}

variable "location" {
  description = "Hetzner location code."
  type        = string
  default     = "nbg1"
}

variable "server_type" {
  description = "Hetzner server type."
  type        = string
  default     = "cpx42"
}

variable "server_image" {
  description = "Hetzner OS image. AlmaLinux 10 — verify the exact slug with `hcloud image list`."
  type        = string
  default     = "alma-10"
}

variable "server_name" {
  description = "Server hostname."
  type        = string
  default     = "watchtower"
}

variable "ssh_public_key" {
  description = "SSH public key (ed25519) used for initial root access."
  type        = string
}

variable "admin_allow_ipv4" {
  description = "IPv4 CIDRs allowed to reach SSH (22/tcp) and WireGuard (51820/udp). Use [\"0.0.0.0/0\"] if mobile."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "admin_allow_ipv6" {
  description = "IPv6 CIDRs allowed to reach SSH and WireGuard."
  type        = list(string)
  default     = ["::/0"]
}

variable "bucket_prefix" {
  description = "Prefix for the three telemetry buckets."
  type        = string
  default     = "watchtower"
}
