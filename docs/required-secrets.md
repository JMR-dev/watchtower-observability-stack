# Required values

This stack needs two kinds of inputs:

1. **Bootstrap / infra values** for OpenTofu.
2. **Runtime secrets** for Ansible and the services it configures.

## OpenTofu / infrastructure

| Variable | Required | Where used | Notes |
| --- | --- | --- | --- |
| `AWS_ACCESS_KEY_ID` | Yes | `tofu init` / state backend | Cloudflare R2 access key for the OpenTofu state bucket. |
| `AWS_SECRET_ACCESS_KEY` | Yes | `tofu init` / state backend | Cloudflare R2 secret key for the OpenTofu state bucket. |
| `hcloud_token` | Yes | Hetzner API provider | Hetzner Cloud API token with read/write access. |
| `hetzner_s3_access_key` | Yes | Hetzner Object Storage provider | S3 access key for the telemetry buckets. |
| `hetzner_s3_secret_key` | Yes | Hetzner Object Storage provider | S3 secret key for the telemetry buckets. |
| `ssh_public_key` | Yes | Hetzner SSH key / initial root access | ed25519 public key used to reach the server on first boot. |
| `admin_allow_ipv4` | Usually | Host firewall / WireGuard allow list | CIDRs allowed to reach SSH and WireGuard. Default is `0.0.0.0/0`, but you should tighten it. |
| `admin_allow_ipv6` | Usually | Host firewall / WireGuard allow list | IPv6 version of the same allow list. Default is `::/0`. |

## Ansible vault values

Store these in `ansible/group_vars/all/vault.yml` and encrypt it with `ansible-vault`:

| Variable | Required | Where used | Notes |
| --- | --- | --- | --- |
| `vault_hetzner_s3_access_key` | Yes | Runtime S3 credentials | Written to `/etc/observability/secrets/s3.env`. |
| `vault_hetzner_s3_secret_key` | Yes | Runtime S3 credentials | Written to `/etc/observability/secrets/s3.env`. |
| `vault_grafana_admin_password` | Yes | Grafana admin login | Used by Grafana and tenant onboarding playbooks. |
| `vault_wireguard_server_private_key` | Yes | WireGuard server config | Server private key for `wg0`. |
| `vault_wireguard_server_public_key` | Yes | WireGuard server config | Server public key shared with clients. |
| `vault_wireguard_peers` | Yes | WireGuard client config | At least one peer entry is needed if you want to connect remotely. |

Each peer entry in `vault_wireguard_peers` should contain:

| Field | Required | Notes |
| --- | --- | --- |
| `name` | Yes | Friendly peer name. |
| `public_key` | Yes | Client WireGuard public key. |
| `allowed_ips` | Yes | Usually a `/32` from `10.8.0.0/24`. |
| `preshared_key` | No | Optional extra protection. |

## Service passwords / tokens

| Variable | Required | Where used | Notes |
| --- | --- | --- | --- |
| `grafana_admin_password` | Yes | Grafana UI and API | Bootstraps Grafana admin access. |

## Minimum set to get the stack running

To fully deploy and log in, you need at least:

- `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
- `hcloud_token`
- `hetzner_s3_access_key` and `hetzner_s3_secret_key`
- `ssh_public_key`
- `vault_hetzner_s3_access_key` and `vault_hetzner_s3_secret_key`
- `vault_grafana_admin_password`
- `vault_wireguard_server_private_key` and `vault_wireguard_server_public_key`
- one `vault_wireguard_peers` entry

## What is not secret

These are still required, but they do not need to be treated as secrets:

- `admin_allow_ipv4`
- `admin_allow_ipv6`
- `bucket_prefix`
- `server_name`
- `location`
- `server_type`

