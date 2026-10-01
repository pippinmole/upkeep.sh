package ingest

import (
	"slices"
	"strings"

	"github.com/pippinmole/upkeep.sh/server/internal/hostfacts"
)

// Docker label allowlist, re-applied on ingest as defense in depth: an
// old, buggy or compromised agent must not get arbitrary labels (which
// routinely carry secrets, e.g. reverse-proxy basic-auth hashes) stored.
// It is a copy of the agent's (agent/internal/collector/types_docker.go:
// dockerLabelKeys, ociLabelPrefix, MaxDockerLabels); both are checked
// against docs/docker-label-allowlist.json by tests, so change all three
// together. PROTOCOL.md "Docker sections", "Never sent".
var dockerLabelKeys = map[string]bool{
	// Docker Compose.
	"com.docker.compose.project":                  true,
	"com.docker.compose.service":                  true,
	"com.docker.compose.container-number":         true,
	"com.docker.compose.oneoff":                   true,
	"com.docker.compose.slug":                     true,
	"com.docker.compose.version":                  true,
	"com.docker.compose.config-hash":              true,
	"com.docker.compose.depends_on":               true,
	"com.docker.compose.image":                    true,
	"com.docker.compose.image-volume-digest":      true,
	"com.docker.compose.image.builder":            true,
	"com.docker.compose.replace":                  true,
	"com.docker.compose.engine":                   true,
	"com.docker.compose.hook":                     true,
	"com.docker.compose.relay":                    true,
	"com.docker.compose.project.config_files":     true,
	"com.docker.compose.project.working_dir":      true,
	"com.docker.compose.project.environment_file": true,
	// docker stack deploy.
	"com.docker.stack.namespace": true,
	"com.docker.stack.image":     true,
	// Swarm task containers (system labels, set by the engine).
	"com.docker.swarm.node.id":      true,
	"com.docker.swarm.service.id":   true,
	"com.docker.swarm.service.name": true,
	"com.docker.swarm.task":         true,
	"com.docker.swarm.task.id":      true,
	"com.docker.swarm.task.name":    true,
}

// ociLabelPrefix is the one label namespace allowed as a prefix.
const ociLabelPrefix = "org.opencontainers.image."

// maxDockerLabelsPerItem matches the agent's MaxDockerLabels.
const maxDockerLabelsPerItem = 64

func dockerLabelAllowed(key string) bool {
	return dockerLabelKeys[key] ||
		(len(key) > len(ociLabelPrefix) && strings.HasPrefix(key, ociLabelPrefix))
}

// dockerLabels keeps only allowlisted keys (matched on the key as sent,
// before any clipping), at most maxDockerLabelsPerItem of them (the
// lexically first, as the agent does), with values clipped. For labels
// from a current agent, which already filtered them, this is the
// identity. Never nil (the columns are NOT NULL).
func dockerLabels(in map[string]string) map[string]string {
	keys := make([]string, 0, len(in))
	for k := range in {
		if dockerLabelAllowed(k) && len(k) <= 256 && k == hostfacts.Clip(k, 256) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	if len(keys) > maxDockerLabelsPerItem {
		keys = keys[:maxDockerLabelsPerItem]
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[k] = hostfacts.Clip(in[k], 1024)
	}
	return out
}
