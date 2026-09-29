# Probe image for agent/test/host-mount/run.sh: a shell, find and curl,
# run in place of the agent with the compose example's exact mounts.
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl ca-certificates >/dev/null \
 && rm -rf /var/lib/apt/lists/*
