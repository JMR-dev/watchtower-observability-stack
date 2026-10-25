# wg-easy for the proxy: the client VPN (wg0) and its web UI. Built from the
# release's source on Alpine, with only what the UI and wg-quick need:
#   - iptables is Alpine's nftables backend. Upstream's image switches to
#     iptables-legacy, which needs kernel modules an nftables host doesn't
#     load and the container can't (the first deploy failed on exactly that).
#   - No AmneziaWG: wg-easy uses it only with EXPERIMENTAL_AWG=true.
#   - Node and pnpm from Alpine and npm; libsql pinned to the lockfile's.
#
# Built natively on the arm64 runner; scripts/build-image.sh checks it and
# scans it with Trivy. Bump the version and the source checksum together; the
# pnpm and libsql versions follow upstream's package.json and pnpm-lock.yaml.
# Alpine is its minor release: the build takes its newest patch release
# (scripts/image-tag.sh --alpine), and the tag says which.
#
# Any change here needs a new tag: a new version label, or else the next
# watchtower.image.revision (back to 1 with a new version).

ARG ALPINE=docker.io/library/alpine:3.24

FROM ${ALPINE} AS build
ARG WG_EASY_VERSION=15.5.0
ARG WG_EASY_SHA256=9ba8cc6c1bfc9c5e4a7649fa26f63f415c1a9c0b56536813343e410f9c9d6347
ARG PNPM_VERSION=12.14.0
ARG LIBSQL_VERSION=0.5.29

RUN apk add --no-cache nodejs npm curl \
 && npm install --global "pnpm@${PNPM_VERSION}"

WORKDIR /build
RUN curl -fsSL -o src.tgz "https://github.com/wg-easy/wg-easy/archive/refs/tags/v${WG_EASY_VERSION}.tar.gz" \
 && echo "${WG_EASY_SHA256}  src.tgz" | sha256sum -c - \
 && tar -xzf src.tgz --strip-components=1 \
 && rm src.tgz

WORKDIR /build/src
RUN pnpm install --frozen-lockfile \
 && pnpm build

# libsql's native binding, which the build output can't bundle
# (https://github.com/nitrojs/nitro/issues/3328): this platform's musl build.
WORKDIR /libsql
RUN npm install --no-save --omit=dev "libsql@${LIBSQL_VERSION}"

FROM ${ALPINE}
LABEL org.opencontainers.image.version="15.5.0"
LABEL watchtower.image.revision="1"
LABEL org.opencontainers.image.source="https://github.com/wg-easy/wg-easy"

# wg-quick is bash and needs ip; iptables runs the interface's hooks.
RUN apk add --no-cache nodejs dumb-init bash iproute2 iptables wireguard-tools

WORKDIR /app
COPY --from=build /build/src/.output /app
COPY --from=build /build/src/server/database/migrations /app/server/database/migrations
COPY --from=build /libsql/node_modules /app/server/node_modules
COPY --from=build --chmod=0755 /build/src/cli/cli.sh /usr/local/bin/cli

ENV DEBUG=Server,WireGuard,Database,CMD,Firewall \
    PORT=51821 \
    HOST=0.0.0.0 \
    INSECURE=false \
    INIT_ENABLED=false \
    DISABLE_IPV6=false \
    DISABLE_VERSION_CHECK=true

CMD ["/usr/bin/dumb-init", "node", "server/index.mjs"]
