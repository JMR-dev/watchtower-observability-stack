# Architecture

## Overview

Watchtower is a single-node observability stack running on a Hetzner CPX42 in
Nuremberg (nbg1). It hosts Mimir (metrics), Loki (logs), Tempo (traces), and
Grafana (UI). Clients ship telemetry over a WireGuard VPN; nothing is exposed
to the public internet.

## Diagram

```
                  Internet
                     │
         ┌───────────┴───────────┐
         │ Hetzner Cloud Firewall│  allow: 22/tcp, 51820/udp
         └───────────┬───────────┘
                     │
              ┌──────┴──────┐
              │ AlmaLinux 10│
              │   CPX42     │
              │             │
              │  nftables   │  default-drop input + fail2ban
              │  ┌──────────┴──────────┐
              │  │ wg0 (10.8.0.1/24)   │  ◄── WireGuard peers
              │  └──┬──────────────────┘
              │     │ all service ports bind to 10.8.0.1
              │  ┌──┴──────────────────────┐
              │  │ Podman observability    │
              │  │ network (172.20.0.0/24) │
              │  │  mimir   :8080 :9095    │
              │  │  loki    :3100          │
              │  │  tempo   :3200/4317/4318│
              │  │  grafana :3000          │
              │  └──┬──────────────────────┘
              │     │
              │  /var/lib/observability  ◄── LUKS2 (xfs)
              └─────┘
                     │ S3 API (HTTPS)
                     ▼
             Hetzner Object Storage (nbg1)
              - watchtower-mimir
              - watchtower-loki
              - watchtower-tempo
```

## Data flow

1. **Clients** run Grafana Alloy with PII scrubbing pipelines (see
   `config/alloy/config.alloy.example`).
2. Alloy ships **logs → Loki**, **traces → Tempo OTLP**, **metrics → Mimir
   remote_write**, all over WireGuard with `X-Scope-OrgID` headers.
3. Mimir/Loki/Tempo write blocks/chunks to Hetzner Object Storage. WALs and
   compactor scratch live on the LUKS-encrypted local volume.
4. Grafana queries Mimir/Loki/Tempo via the `observability` Podman bridge
   (container DNS), with tenant header injected per Org's datasource config.

## Components and ports

| Service  | Container | Bind             | Public? |
|----------|-----------|------------------|---------|
| Mimir    | mimir     | 10.8.0.1:8080,9095| no     |
| Loki     | loki      | 10.8.0.1:3100    | no      |
| Tempo    | tempo     | 10.8.0.1:3200, OTLP 4317/4318 | no |
| Grafana  | grafana   | 10.8.0.1:3000    | no      |

## Storage

| Layer       | Backend        | Encryption                  |
|-------------|----------------|-----------------------------|
| Long-term   | Hetzner S3     | Server-side (Hetzner SSE)   |
| Local WAL   | LUKS2 + xfs    | At-rest (LUKS2 on /dev/sdX or loop) |
| Transit     | WireGuard      | ChaCha20-Poly1305           |

## Lifecycle

- **OpenTofu** provisions the server, firewall, and S3 buckets (state in
  Cloudflare R2).
- **Ansible** configures AlmaLinux, LUKS, nftables + fail2ban, WireGuard, and deploys
  the Podman Quadlets.
- **systemd Quadlet generator** turns `*.container` files into
  `mimir.service`, `loki.service`, `tempo.service`, `grafana.service`.
