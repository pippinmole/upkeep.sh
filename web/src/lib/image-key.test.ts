/// <reference types="bun" />

import { describe, expect, test } from "bun:test";
import { registryOf } from "./image-key";

describe("registryOf", () => {
  test("Docker Hub short names and namespaced repos", () => {
    expect(registryOf("nginx")).toBe("docker.io");
    expect(registryOf("library/nginx")).toBe("docker.io");
    expect(registryOf("grafana/grafana")).toBe("docker.io");
  });

  test("explicit Docker Hub hosts normalise to docker.io", () => {
    expect(registryOf("docker.io/library/nginx")).toBe("docker.io");
    expect(registryOf("index.docker.io/library/nginx")).toBe("docker.io");
  });

  test("a first component with a dot, a port or localhost is the host", () => {
    expect(registryOf("ghcr.io/org/app")).toBe("ghcr.io");
    expect(registryOf("quay.io/prometheus/node-exporter")).toBe("quay.io");
    expect(registryOf("registry.gitlab.com/group/project/image")).toBe("registry.gitlab.com");
    expect(registryOf("europe-west1-docker.pkg.dev/p/r/i")).toBe("europe-west1-docker.pkg.dev");
    expect(registryOf("localhost:5000/app")).toBe("localhost:5000");
    expect(registryOf("localhost/app")).toBe("localhost");
    expect(registryOf("myregistry:5000/app")).toBe("myregistry:5000");
    expect(registryOf("GHCR.IO/org/app")).toBe("ghcr.io");
  });

  test("empty and pseudo repos", () => {
    expect(registryOf("")).toBe("");
    expect(registryOf("_untagged")).toBe("docker.io");
  });
});
