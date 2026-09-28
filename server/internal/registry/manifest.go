package registry

import (
	"encoding/json"
	"strings"
)

// The subset of the OCI image-spec / Docker v2 manifest formats we read.

// Descriptor points at a manifest or blob by digest.
type Descriptor struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	Platform     *Platform         `json:"platform,omitempty"`
}

// Platform is an image platform as the engine reports it (container_images
// os / arch / variant).
type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

func (p Platform) String() string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// Manifest is an index (Manifests set) or an image / artifact manifest
// (Config and Layers set).
type Manifest struct {
	MediaType    string       `json:"mediaType"`
	ArtifactType string       `json:"artifactType,omitempty"`
	Config       Descriptor   `json:"config"`
	Layers       []Descriptor `json:"layers"`
	Manifests    []Descriptor `json:"manifests"`
}

// IsIndex reports whether m is an index / manifest list.
func (m Manifest) IsIndex() bool {
	return m.MediaType == MediaTypeOCIIndex || m.MediaType == MediaTypeDockerList ||
		(m.MediaType == "" && len(m.Manifests) > 0)
}

func parseManifest(host string, b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return m, newErr(KindTransient, host, "bad manifest: %v", err)
	}
	return m, nil
}

// BuildKit attestation manifests in an index (docs.docker.com "Attestation
// storage"): an entry with these annotations, whose layers are in-toto
// statements annotated with their predicate type.
const (
	annotationRefType   = "vnd.docker.reference.type"
	annotationRefDigest = "vnd.docker.reference.digest"
	refTypeAttestation  = "attestation-manifest"
	annotationPredicate = "in-toto.io/predicate-type"
)

// platformDescriptor picks the index entry for p. Attestation entries
// (platform unknown/unknown) never match. The variant must match exactly,
// except that arm64's "v8" and "" are the same platform (engines and
// indexes disagree on writing it).
func platformDescriptor(idx Manifest, p Platform) (Descriptor, bool) {
	norm := func(arch, v string) string {
		if arch == "arm64" && v == "v8" {
			return ""
		}
		return v
	}
	for _, d := range idx.Manifests {
		if d.Platform == nil || d.Annotations[annotationRefType] != "" {
			continue
		}
		if strings.EqualFold(d.Platform.OS, p.OS) && strings.EqualFold(d.Platform.Architecture, p.Architecture) &&
			norm(d.Platform.Architecture, d.Platform.Variant) == norm(p.Architecture, p.Variant) {
			return d, true
		}
	}
	return Descriptor{}, false
}

// attestationFor finds the attestation manifest entry for the platform
// manifest digest in an index.
func attestationFor(idx Manifest, manifestDigest string) (Descriptor, bool) {
	for _, d := range idx.Manifests {
		if d.Annotations[annotationRefType] == refTypeAttestation && d.Annotations[annotationRefDigest] == manifestDigest {
			return d, true
		}
	}
	return Descriptor{}, false
}
