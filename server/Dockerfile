# Cross-compiles on the builder's platform (see agent/Dockerfile).
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The binaries ship in one image: `api` (default entrypoint), `worker` and
# `migrate` (compose overrides the entrypoint for those services; migrate
# carries the schema migrations embedded from migrations/).
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/ ./cmd/api ./cmd/worker ./cmd/migrate

FROM alpine:3.24
RUN apk add --no-cache ca-certificates
COPY --from=build /out/api /api
COPY --from=build /out/worker /worker
COPY --from=build /out/migrate /migrate
ENTRYPOINT ["/api"]
