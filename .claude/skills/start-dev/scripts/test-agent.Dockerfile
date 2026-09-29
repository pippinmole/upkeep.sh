# Standalone test image for running the agent WITHOUT a host bind mount.
#
# The production agent/Dockerfile is `FROM scratch` and relies entirely on
# its read-only /host and /host-extra binds to see the real host's
# /etc/os-release and dpkg database (see agent/docker-compose.example.yml). That's fine on a real Linux VPS,
# but on macOS (and Windows without WSL) there's no real Debian/Ubuntu
# filesystem to mount — Docker Desktop's own VM isn't one either.
#
# This image sidesteps the whole problem: it's built FROM a real ubuntu
# base, so it has its OWN genuine /etc/os-release and dpkg database, and a
# self-referential `/host -> /` symlink satisfies the agent's hardcoded
# /host/... paths with nothing to mount at all. Same trick as the /host
# symlink used for the WSL path in test-agent-windows.sh, just baked into
# the image instead of set up by hand.
FROM golang:1.27.1-alpine AS build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/agent ./cmd/agent

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sfn / /host
COPY --from=build /out/agent /agent
ENTRYPOINT ["/agent"]
