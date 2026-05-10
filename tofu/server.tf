resource "hcloud_ssh_key" "admin" {
  name       = "${var.server_name}-admin"
  public_key = var.ssh_public_key
}

resource "hcloud_firewall" "watchtower" {
  name = "${var.server_name}-fw"

  # SSH
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = concat(var.admin_allow_ipv4, var.admin_allow_ipv6)
  }

  # WireGuard
  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "51820"
    source_ips = concat(var.admin_allow_ipv4, var.admin_allow_ipv6)
  }

  # ICMP (ping) — useful for ops, optional
  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_primary_ip" "ipv4" {
  name            = "${var.server_name}-ipv4"
  type            = "ipv4"
  assignee_type   = "server"
  auto_delete     = false
}

resource "hcloud_primary_ip" "ipv6" {
  name            = "${var.server_name}-ipv6"
  type            = "ipv6"
  assignee_type   = "server"
  auto_delete     = false
}

resource "hcloud_volume" "observability" {
  name     = "${var.server_name}-observability"
  size     = var.observability_volume_size_gb
  location = var.location

  labels = {
    role        = "observability-data"
    managed_by  = "opentofu"
    environment = "prod"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "hcloud_volume_attachment" "observability" {
  volume_id = hcloud_volume.observability.id
  server_id = hcloud_server.watchtower.id
  automount = false
}

resource "hcloud_server" "watchtower" {
  name         = var.server_name
  server_type  = var.server_type
  image        = var.server_image
  location     = var.location
  ssh_keys     = [hcloud_ssh_key.admin.id]
  firewall_ids = [hcloud_firewall.watchtower.id]

  public_net {
    ipv4_enabled = true
    ipv4         = hcloud_primary_ip.ipv4.id
    ipv6_enabled = true
    ipv6         = hcloud_primary_ip.ipv6.id
  }

  user_data = file("${path.module}/cloud-init.yaml")

  labels = {
    role        = "observability"
    managed_by  = "opentofu"
    environment = "prod"
  }

  lifecycle {
    ignore_changes = [user_data, ssh_keys]
  }
}
