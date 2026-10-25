# syntax=docker/dockerfile:1
#
# Caddy for the proxy (amd64), built with xcaddy:
#   - coraza-caddy + the OWASP Core Rule Set, embedded at build time (WAF);
#   - caddy-dns/googleclouddns, for ACME DNS-01 against the Cloud DNS zone
#     watchtower.jasonmross.dev (the endpoint is private, so HTTP-01 cannot
#     work).
# The runtime image ships only the binary and CA certificates, and runs as
# UID 1000. scripts/build-image.sh builds it, validates the proxy's rendered
# Caddyfile with it and scans it with Trivy.
#
# Base images are pinned by digest; bump the tag and digest together.

ARG GO_IMAGE=docker.io/library/golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4
ARG RUNTIME_IMAGE=docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

FROM ${GO_IMAGE} AS builder

ARG XCADDY_VERSION=v0.4.7
ARG CADDY_VERSION=v2.11.7
ARG CORAZA_CADDY_VERSION=v2.6.2
ARG CORAZA_CRS_VERSION=v4.25.0
ARG GOOGLECLOUDDNS_VERSION=v1.1.0
# Transitive Go modules forced above what Caddy and the plugins require, for
# fixes Trivy flags that no Caddy or plugin release has picked up yet (the
# same pin as vaultwarden-deployment). Space-separated module@version; each
# becomes an xcaddy --replace. Drop an entry once Caddy or a plugin requires
# that version or newer, since a replace also blocks upgrades.
#   golang.org/x/net: CVE-2026-78669, fixed in v0.60.0; Caddy v2.11.7 and
#   coraza-caddy v2.6.2 still require older releases.
ARG GO_MODULE_PINS="golang.org/x/net@v0.61.0"

ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local

RUN go install "github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}"

RUN set --; for pin in ${GO_MODULE_PINS}; do set -- "$@" --replace "${pin%@*}=${pin}"; done; \
    xcaddy build "${CADDY_VERSION}" \
    --output /usr/local/bin/caddy \
    --with "github.com/corazawaf/coraza-caddy/v2@${CORAZA_CADDY_VERSION}" \
    --with "github.com/corazawaf/coraza-coreruleset/v4@${CORAZA_CRS_VERSION}" \
    --with "github.com/caddy-dns/googleclouddns@${GOOGLECLOUDDNS_VERSION}" \
    "$@"

# A dropped --with still builds a working Caddy, one that fails only at
# runtime (no WAF directive, no DNS-01 provider). Fail the build instead.
RUN /usr/local/bin/caddy list-modules | grep -qx 'http.handlers.waf' \
    && /usr/local/bin/caddy list-modules | grep -qx 'dns.providers.googleclouddns'

# ── Runtime image ──────────────────────────────────────────────────────────────
FROM ${RUNTIME_IMAGE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/caddy /usr/bin/caddy

RUN groupadd --system --gid 1000 caddy \
    && useradd --system --uid 1000 --gid caddy --no-create-home caddy

USER 1000:1000

EXPOSE 443 3100 3200 4317 4318 8080 51821

ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
