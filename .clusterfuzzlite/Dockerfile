# ClusterFuzzLite builder image. The workflows build it with the repository
# root as the context, so the root .dockerignore applies. It keeps out .git,
# whose remote URL contains the GitHub token when the action clones with one.
#
# The base image is the v1 tag ClusterFuzzLite documents, pinned to the digest
# it pointed at on 2026-10-12. Dependabot (docker, /.clusterfuzzlite) proposes
# the new digest when v1 moves; to check by hand, run
#   docker buildx imagetools inspect gcr.io/oss-fuzz-base/base-builder-go:v1
FROM gcr.io/oss-fuzz-base/base-builder-go:v1@sha256:1dbadefbb28c6bfd796c64d9c2115977deb8f19494533cc5a3b724c3441df23d

# The image ships Go 1.27.1, which the default GOTOOLCHAIN=auto would build
# with because it is newer than the go line in go.mod. Build with the Go
# release go.mod names instead, as CI (setup-go with go-version-file) and the
# release image (golang:1.26.11-bookworm) do. The go command downloads it from
# the Go module proxy and checks it against the Go checksum database. Keep it
# in step with go.mod: once go.mod asks for a newer Go, the build fails until
# this line is updated.
ENV GOTOOLCHAIN=go1.26.11
RUN go version

COPY . $SRC/zeroauthy
WORKDIR $SRC/zeroauthy
COPY .clusterfuzzlite/build.sh $SRC/
