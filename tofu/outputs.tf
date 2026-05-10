output "server_ipv4" {
  description = "Public IPv4 of the watchtower server."
  value       = hcloud_primary_ip.ipv4.ip_address
}

output "server_ipv6" {
  description = "Public IPv6 of the watchtower server."
  value       = hcloud_primary_ip.ipv6.ip_address
}

output "server_id" {
  value = hcloud_server.watchtower.id
}

output "buckets" {
  description = "Telemetry bucket names."
  value       = { for k, v in aws_s3_bucket.telemetry : k => v.bucket }
}

output "s3_endpoint" {
  description = "Hetzner Object Storage endpoint URL."
  value       = "https://${var.location}.your-objectstorage.com"
}

output "ansible_inventory" {
  description = "Drop-in inventory snippet for Ansible."
  value = yamlencode({
    all = {
      hosts = {
        watchtower = {
          ansible_host               = hcloud_primary_ip.ipv4.ip_address
          ansible_user               = "root"
          ansible_python_interpreter = "/usr/bin/python3"
        }
      }
    }
  })
}
