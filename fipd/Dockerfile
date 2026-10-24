# syntax=docker/dockerfile:1
#
# fipd: a static binary on distroless, non-root (UID 65532).
# Build context: the fipd/ directory. Base images are pinned by digest.

ARG GO_IMAGE=docker.io/library/golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

FROM ${GO_IMAGE} AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/fipd .

FROM ${RUNTIME_IMAGE}
COPY --from=builder /out/fipd /fipd
USER 65532:65532
ENTRYPOINT ["/fipd"]
