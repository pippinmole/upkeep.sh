# The build stage runs on the builder's own platform and cross-compiles for
# the target (release.yml builds linux/amd64 and linux/arm64), so the Go
# build never runs under QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/agent ./cmd/agent

FROM scratch
COPY --from=build /out/agent /agent
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/agent"]
