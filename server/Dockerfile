# Cross-compiles on the builder's platform (see agent/Dockerfile).
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Both binaries ship in one image: `api` (default entrypoint) and `worker`
# (compose overrides the entrypoint for the worker service).
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/ ./cmd/api ./cmd/worker

FROM alpine:3.24
RUN apk add --no-cache ca-certificates
COPY --from=build /out/api /api
COPY --from=build /out/worker /worker
ENTRYPOINT ["/api"]
