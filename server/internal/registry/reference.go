// Package registry is a small, read-only OCI Distribution client for
// fetching a container image's SBOM attestation by digest (TASKS.md Phase
// 2a "Worker: image_sbom", DECISIONS.md "Container image
// vulnerabilities"). It only ever GETs manifests and blobs by digest,
// anonymously (Bearer token flow), with optional platform-wide Docker Hub
// credentials that only raise the pull rate limit.
//
// Every connection goes through netguard (public addresses only, checked
// at dial time, also after redirects: registries redirect blob GETs to a
// CDN, which is allowed but re-checked). Responses are size-capped and
// their content digest is verified against the digest asked for, so a
// registry, CDN or proxy can't substitute content. A 429 backs the whole
// registry off (Retry-After respected) without failing the image.
//
// The standard library is enough for this: the OCI API surface we need is
// four GET endpoints and one token exchange.
package registry

import (
	"fmt"
	"regexp"
	"strings"
)

// Docker Hub's names: images are named "docker.io/…" (or nothing), the
// API lives on registry-1.docker.io and single-component names are in the
// "library/" namespace (the official images).
const (
	DockerHubDomain = "docker.io"
	DockerHubAPI    = "registry-1.docker.io"
)

// Ref is a parsed repo digest ("postgres@sha256:…").
type Ref struct {
	// Domain is the registry as named in the reference, normalised
	// ("docker.io" for Docker Hub, however it was written).
	Domain string
	// Host is where the API is served ("registry-1.docker.io" for Docker
	// Hub, else Domain), including a port if one was given.
	Host string
	// Repository is the path within the registry ("library/postgres").
	Repository string
	// Digest is "sha256:<64 hex>".
	Digest string
}

func (r Ref) String() string { return r.Domain + "/" + r.Repository + "@" + r.Digest }

// IsDockerHub reports whether the reference is on Docker Hub.
func (r Ref) IsDockerHub() bool { return r.Domain == DockerHubDomain }

var (
	digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	// A repository path component (distribution/reference grammar):
	// lowercase alphanumerics separated by '.', '_', '__' or '-'s.
	pathComponentRE = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*$`)
	// A registry domain: host name or IP (IPv6 in brackets), optional port.
	domainRE = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*|\[[0-9a-fA-F:.]+\])(?::[0-9]{1,5})?$`)
)

// ParseRepoDigest parses a repo digest as the Docker engine reports it
// (RepoDigests): "[domain/]path@sha256:…", optionally with a tag before
// the digest. Only sha256 digests are accepted (they are verified).
//
// The first path component is a domain if it contains '.' or ':' or is
// "localhost" (the distribution/reference rule); otherwise the image is on
// Docker Hub. Docker Hub names are normalised: "index.docker.io" and
// "registry-1.docker.io" become "docker.io", and single-component names
// get the "library/" namespace.
func ParseRepoDigest(s string) (Ref, error) {
	name, digest, ok := strings.Cut(s, "@")
	if !ok {
		return Ref{}, fmt.Errorf("repo digest %q: no digest", s)
	}
	if !digestRE.MatchString(digest) {
		return Ref{}, fmt.Errorf("repo digest %q: unsupported digest (want sha256)", s)
	}
	// A tag after the last path separator ("repo:tag@sha256:…").
	if i := strings.LastIndexByte(name, ':'); i > strings.LastIndexByte(name, '/') {
		name = name[:i]
	}

	domain, path := DockerHubDomain, name
	if first, rest, found := strings.Cut(name, "/"); found &&
		(strings.ContainsAny(first, ".:") || first == "localhost" || strings.HasPrefix(first, "[")) {
		domain, path = first, rest
	}
	if !domainRE.MatchString(domain) {
		return Ref{}, fmt.Errorf("repo digest %q: invalid registry %q", s, domain)
	}
	switch strings.ToLower(domain) {
	case DockerHubDomain, "index.docker.io", DockerHubAPI:
		domain = DockerHubDomain
	}
	if domain == DockerHubDomain && !strings.Contains(path, "/") {
		path = "library/" + path
	}
	if path == "" || len(path) > 255 {
		return Ref{}, fmt.Errorf("repo digest %q: invalid repository", s)
	}
	for _, c := range strings.Split(path, "/") {
		if !pathComponentRE.MatchString(c) {
			return Ref{}, fmt.Errorf("repo digest %q: invalid repository %q", s, path)
		}
	}

	host := domain
	if domain == DockerHubDomain {
		host = DockerHubAPI
	}
	return Ref{Domain: domain, Host: host, Repository: path, Digest: digest}, nil
}
