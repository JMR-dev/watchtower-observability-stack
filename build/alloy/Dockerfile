# Grafana Alloy for the nodes (roles/gcppull): pulls Gitea CI's logs and metrics
# from GCP. Alpine with the release binary, checked against the release's
# SHA256SUMS, and only what the binary needs:
#   - gcompat: the release binary is linked against glibc (it reads the journal
#     through cgo), and Alpine is musl.
#   - ca-certificates: Pub/Sub, Cloud Monitoring and Google's token endpoint.
#
# Built natively on the arm64 runner; scripts/build-image.sh checks it and
# scans it with Trivy. Bump the version and both checksums together. The amd64
# zip is only for local tests. Alpine is its minor release: the build takes its
# newest patch release (scripts/image-tag.sh --alpine), and the tag says which.
#
# Any change here needs a new tag: a new version label, or else the next
# watchtower.image.revision (back to 1 with a new version).

ARG ALPINE=docker.io/library/alpine:3.24

FROM ${ALPINE} AS download
ARG TARGETARCH
ARG ALLOY_VERSION=1.21.3
ARG ALLOY_SHA256_ARM64=ca2f383cc60491877b21aef50c54af6a198f6c861c2c4b80f41ec49ad73b1b93
ARG ALLOY_SHA256_AMD64=50d23af2d0f98c00beac6ce9a365693e60f87fb76b6cad6fe1d161e80588af6d

RUN apk add --no-cache curl unzip

WORKDIR /download
RUN case "${TARGETARCH}" in \
      arm64) sum="${ALLOY_SHA256_ARM64}" ;; \
      amd64) sum="${ALLOY_SHA256_AMD64}" ;; \
      *) echo "no pinned Alloy for ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o alloy.zip "https://github.com/grafana/alloy/releases/download/v${ALLOY_VERSION}/alloy-linux-${TARGETARCH}.zip" \
 && echo "${sum}  alloy.zip" | sha256sum -c - \
 && unzip -q alloy.zip \
 && install -m 0755 "alloy-linux-${TARGETARCH}" /usr/local/bin/alloy

FROM ${ALPINE}
LABEL org.opencontainers.image.version="1.21.3"
LABEL watchtower.image.revision="1"
LABEL org.opencontainers.image.source="https://github.com/grafana/alloy"

# Every package upgraded to the build day's (IMAGE_DATE, set by
# scripts/build-image.sh): a new day misses the build cache from here, so the
# upgrade really runs.
ARG IMAGE_DATE=unset
LABEL watchtower.image.date="${IMAGE_DATE}"
RUN apk upgrade --no-cache \
 && apk add --no-cache ca-certificates gcompat \
 && addgroup -S -g 473 alloy \
 && adduser -S -D -H -u 473 -G alloy alloy

COPY --from=download /usr/local/bin/alloy /usr/bin/alloy

USER 473:473

ENTRYPOINT ["/usr/bin/alloy"]
CMD ["--version"]
