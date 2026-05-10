# syntax=docker/dockerfile:1
#
# Multi-stage build: xcaddy compiles Caddy with the Coraza WAF plugin and the
# OWASP Core Rule Set embedded at build time, then the final image is a minimal
# debian:bookworm-slim layer that ships only the compiled binary.
#
# Rebuild whenever the ARG versions below change; Ansible will detect the
# Dockerfile checksum change and re-run `podman build`.

FROM golang:1.23-bookworm AS builder

ARG XCADDY_VERSION=v0.3.5
ARG CADDY_VERSION=v2.9.1
ARG CORAZA_CADDY_VERSION=v2.5.0
ARG CORAZA_CRS_VERSION=v4.7.0

RUN go install "github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}"

RUN xcaddy build "${CADDY_VERSION}" \
    --with "github.com/corazawaf/coraza-caddy/v2@${CORAZA_CADDY_VERSION}" \
    --with "github.com/corazawaf/coraza-coreruleset@${CORAZA_CRS_VERSION}"

# ── Runtime image ──────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/caddy /usr/bin/caddy

RUN groupadd --system --gid 1000 caddy \
    && useradd --system --uid 1000 --gid caddy --no-create-home caddy

EXPOSE 80 3100 3200 4317 4318 8080

ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
