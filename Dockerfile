# syntax=docker/dockerfile:1
#
# zeroauthy container image. Build: docker build -t zeroauthy .
# Multi-arch: docker buildx build --platform linux/amd64,linux/arm64 .
#
# Go cross-compiles natively on the build platform, and the runtime stage has
# no RUN steps, so arm64 images build without emulation. The runtime image
# ships Node.js because Actions, custom database scripts and social profile
# scripts run in Node (social scripts need Node 25+; see docs/social-connections.md).

FROM --platform=$BUILDPLATFORM golang:1.26.11-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
      -ldflags "-s -w -buildid= -X main.version=${VERSION}" \
      -o /out/zeroauthy ./cmd/zeroauthy \
 && mkdir -p /out/data

FROM node:26-bookworm-slim
ARG VERSION=dev
LABEL org.opencontainers.image.title="zeroauthy" \
      org.opencontainers.image.description="Open-source, Auth0-compatible identity server" \
      org.opencontainers.image.source="https://github.com/occupysaas/zeroauthy" \
      org.opencontainers.image.documentation="https://github.com/occupysaas/zeroauthy/blob/main/docs/configuration.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/zeroauthy /usr/local/bin/zeroauthy
COPY --from=build --chown=node:node /out/data /data
COPY LICENSE NOTICE /usr/share/doc/zeroauthy/
# Defaults for a single-container start: SQLite in the /data volume, migrated
# on start. Override any setting with ZEROAUTHY_* variables or --config.
ENV ZEROAUTHY_SERVER__LISTEN=:8080 \
    ZEROAUTHY_STORAGE__DSN=sqlite:///data/zeroauthy.db \
    ZEROAUTHY_STORAGE__AUTO_MIGRATE=true
USER node
WORKDIR /data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["zeroauthy"]
CMD ["serve"]
