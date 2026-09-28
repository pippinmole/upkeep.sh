package registry

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
)

// SBOM document formats.
const (
	FormatSPDX      = "spdx-json"
	FormatCycloneDX = "cyclonedx-json"
)

// Where an SBOM was found.
const (
	ViaAttestationManifest = "attestation-manifest" // BuildKit / Docker attestation in the index
	ViaReferrers           = "referrers"            // OCI 1.1 referrers API
)

// SBOM is an image's SBOM as the registry holds it.
type SBOM struct {
	Format string // FormatSPDX | FormatCycloneDX
	// Document is the SBOM itself (unwrapped from its in-toto statement).
	Document []byte
	Via      string
	Ref      Ref
	// ManifestDigest is the platform manifest the SBOM describes.
	ManifestDigest string
}

// FetchSBOM finds and fetches the SBOM of one platform of the image ref
// names. imageID is the engine's image id for that platform
// (container_images.image_id): the index digest on the containerd image
// store, the config digest on the classic one. The registry's content is
// only used if imageID is one of the index, platform manifest or config
// digests, so a repo digest reported next to another image's id can't
// attach this image's package list to it.
//
// Order: the BuildKit attestation manifest for the platform in the index,
// then the OCI referrers of the platform manifest. SPDX is preferred over
// CycloneDX within each. KindNoAttestation when neither has an SBOM.
func (c *Client) FetchSBOM(ctx context.Context, ref Ref, p Platform, imageID string) (*SBOM, error) {
	b, err := c.getManifest(ctx, ref, ref.Digest)
	if err != nil {
		return nil, err
	}
	top, err := parseManifest(ref.Host, b)
	if err != nil {
		return nil, err
	}

	var (
		manifestDigest = ref.Digest
		single         *Manifest // the platform manifest, once fetched
	)
	if top.IsIndex() {
		d, ok := platformDescriptor(top, p)
		if !ok {
			return nil, newErr(KindMismatch, ref.Host, "platform %s not in %s", p, ref)
		}
		manifestDigest = d.Digest
	} else {
		single = &top
	}
	if imageID != ref.Digest && imageID != manifestDigest {
		if single == nil {
			b, err := c.getManifest(ctx, ref, manifestDigest)
			if err != nil {
				return nil, err
			}
			m, err := parseManifest(ref.Host, b)
			if err != nil {
				return nil, err
			}
			single = &m
		}
		if single.Config.Digest != imageID {
			return nil, newErr(KindMismatch, ref.Host, "image %s is not %s (%s)", imageID, ref, p)
		}
	}

	if top.IsIndex() {
		if att, ok := attestationFor(top, manifestDigest); ok {
			s, err := c.fromAttestationManifest(ctx, ref, att, manifestDigest)
			if err == nil || KindOf(err) != KindNoAttestation {
				return s, err
			}
		}
	}
	return c.fromReferrers(ctx, ref, manifestDigest)
}

// sbomPredicate maps an in-toto predicate type to an SBOM format ("" =
// not an SBOM). Versioned forms ("https://spdx.dev/Document/v2.3") count.
func sbomPredicate(t string) string {
	switch {
	case t == "https://spdx.dev/Document" || strings.HasPrefix(t, "https://spdx.dev/Document/"):
		return FormatSPDX
	case t == "https://cyclonedx.org/bom" || strings.HasPrefix(t, "https://cyclonedx.org/bom/"):
		return FormatCycloneDX
	}
	return ""
}

// sbomMediaType maps a referrer's artifact type or a layer media type to
// an SBOM format ("" = not a plain SBOM document).
func sbomMediaType(t string) string {
	t, _, _ = strings.Cut(t, ";")
	switch strings.TrimSpace(t) {
	case "application/spdx+json", "text/spdx+json":
		return FormatSPDX
	case "application/vnd.cyclonedx+json":
		return FormatCycloneDX
	}
	return ""
}

const mediaTypeInToto = "application/vnd.in-toto+json"

// formatRank orders candidates: SPDX first.
func formatRank(f string) int {
	if f == FormatSPDX {
		return 0
	}
	return 1
}

func (c *Client) fromAttestationManifest(ctx context.Context, ref Ref, att Descriptor, manifestDigest string) (*SBOM, error) {
	b, err := c.getManifest(ctx, ref, att.Digest)
	if err != nil {
		return nil, err
	}
	am, err := parseManifest(ref.Host, b)
	if err != nil {
		return nil, err
	}
	var layers []Descriptor
	for _, l := range am.Layers {
		if sbomPredicate(l.Annotations[annotationPredicate]) != "" {
			layers = append(layers, l)
		}
	}
	slices.SortStableFunc(layers, func(a, b Descriptor) int {
		return formatRank(sbomPredicate(a.Annotations[annotationPredicate])) -
			formatRank(sbomPredicate(b.Annotations[annotationPredicate]))
	})
	for _, l := range layers {
		blob, err := c.getBlob(ctx, ref, l.Digest, l.Size)
		if err != nil {
			return nil, err
		}
		format, doc, err := unwrapStatement(blob, manifestDigest)
		if err != nil {
			return nil, &Error{Kind: KindTransient, Host: ref.Host, Err: err}
		}
		if format == "" {
			continue // not an SBOM after all, or about another subject
		}
		return &SBOM{Format: format, Document: doc, Via: ViaAttestationManifest, Ref: ref, ManifestDigest: manifestDigest}, nil
	}
	return nil, newErr(KindNoAttestation, ref.Host, "attestation manifest %s has no SBOM", att.Digest)
}

// fromReferrers looks the platform manifest's SBOMs up through the OCI
// 1.1 referrers API. A registry without it (404, 400, 405, 501) simply
// has none.
func (c *Client) fromReferrers(ctx context.Context, ref Ref, manifestDigest string) (*SBOM, error) {
	b, _, err := c.get(ctx, ref, "/referrers/"+manifestDigest, MediaTypeOCIIndex, c.cfg.MaxManifestBytes, c.cfg.RequestTimeout)
	var e *Error
	if errors.As(err, &e) && slices.Contains([]int{http.StatusNotFound, http.StatusBadRequest,
		http.StatusMethodNotAllowed, http.StatusNotImplemented}, e.Status) {
		return nil, newErr(KindNoAttestation, ref.Host, "no SBOM attestation for %s (no referrers API)", ref)
	}
	if err != nil {
		return nil, err
	}
	idx, err := parseManifest(ref.Host, b)
	if err != nil {
		return nil, err
	}
	var refs []Descriptor
	for _, d := range idx.Manifests {
		if sbomMediaType(d.ArtifactType) != "" {
			refs = append(refs, d)
		}
	}
	slices.SortStableFunc(refs, func(a, b Descriptor) int {
		return formatRank(sbomMediaType(a.ArtifactType)) - formatRank(sbomMediaType(b.ArtifactType))
	})
	for _, d := range refs {
		b, err := c.getManifest(ctx, ref, d.Digest)
		if err != nil {
			return nil, err
		}
		m, err := parseManifest(ref.Host, b)
		if err != nil {
			return nil, err
		}
		for _, l := range m.Layers {
			format := sbomMediaType(l.MediaType)
			if format == "" && l.MediaType != mediaTypeInToto {
				continue
			}
			blob, err := c.getBlob(ctx, ref, l.Digest, l.Size)
			if err != nil {
				return nil, err
			}
			if f, doc, err := unwrapStatement(blob, manifestDigest); err == nil && f != "" {
				format, blob = f, doc // an in-toto statement around the SBOM
			} else if l.MediaType == mediaTypeInToto {
				continue
			}
			return &SBOM{Format: format, Document: blob, Via: ViaReferrers, Ref: ref, ManifestDigest: manifestDigest}, nil
		}
	}
	return nil, newErr(KindNoAttestation, ref.Host, "no SBOM attestation for %s", ref)
}
