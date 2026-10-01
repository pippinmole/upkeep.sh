package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// Pulling an image's content (server-side Syft, internal/imagescan): the
// platform manifest, then each layer blob streamed to the caller's writer
// and verified against its digest. Same rules as SBOM fetching: GETs by
// digest only, through netguard, every byte verified.

// resolve fetches ref's top manifest and picks the platform manifest for
// p. The registry's content only belongs to the image if imageID is the
// index, platform manifest or config digest (see FetchSBOM); otherwise
// KindMismatch. With needManifest (or when the id check needs it) the
// platform manifest is fetched and returned too.
func (c *Client) resolve(ctx context.Context, ref Ref, p Platform, imageID string, needManifest bool) (top Manifest, manifestDigest string, single *Manifest, err error) {
	b, err := c.getManifest(ctx, ref, ref.Digest)
	if err != nil {
		return top, "", nil, err
	}
	if top, err = parseManifest(ref.Host, b); err != nil {
		return top, "", nil, err
	}

	manifestDigest = ref.Digest
	if top.IsIndex() {
		d, ok := platformDescriptor(top, p)
		if !ok {
			return top, "", nil, newErr(KindMismatch, ref.Host, "platform %s not in %s", p, ref)
		}
		manifestDigest = d.Digest
	} else {
		single = &top
	}
	idOK := imageID == ref.Digest || imageID == manifestDigest
	if single == nil && (needManifest || !idOK) {
		b, err := c.getManifest(ctx, ref, manifestDigest)
		if err != nil {
			return top, "", nil, err
		}
		m, err := parseManifest(ref.Host, b)
		if err != nil {
			return top, "", nil, err
		}
		single = &m
	}
	if !idOK && single.Config.Digest != imageID {
		return top, "", nil, newErr(KindMismatch, ref.Host, "image %s is not %s (%s)", imageID, ref, p)
	}
	return top, manifestDigest, single, nil
}

// Image is one platform image of a repo digest, checked against the
// engine's image id.
type Image struct {
	Ref            Ref
	ManifestDigest string
	// Config is the image config blob's descriptor, Layers the layer blobs
	// in order (lowest first).
	Config Descriptor
	Layers []Descriptor
}

// ResolveImage finds the platform manifest of the image ref names for p
// (imageID as for FetchSBOM). KindMismatch when the platform is missing,
// the id doesn't match, or the manifest isn't an image manifest.
func (c *Client) ResolveImage(ctx context.Context, ref Ref, p Platform, imageID string) (*Image, error) {
	_, manifestDigest, m, err := c.resolve(ctx, ref, p, imageID, true)
	if err != nil {
		return nil, err
	}
	if m.IsIndex() || m.Config.Digest == "" {
		return nil, newErr(KindMismatch, ref.Host, "%s (%s) is not an image manifest", ref, p)
	}
	for _, l := range append([]Descriptor{m.Config}, m.Layers...) {
		if !digestRE.MatchString(l.Digest) || l.Size < 0 {
			return nil, newErr(KindMismatch, ref.Host, "%s: bad descriptor %q", ref, l.Digest)
		}
	}
	return &Image{Ref: ref, ManifestDigest: manifestDigest, Config: m.Config, Layers: m.Layers}, nil
}

// DownloadBlob streams the blob d of ref's repository to w (following the
// redirect to a CDN) and verifies its content digest and size. maxBytes
// caps it (KindTooLarge, checked against the descriptor before
// downloading); ctx bounds the time. An error from w (a disk cap) comes
// back as is. On a digest mismatch w has received unverified bytes: the
// caller must discard them.
func (c *Client) DownloadBlob(ctx context.Context, ref Ref, d Descriptor, maxBytes int64, w io.Writer) error {
	if !digestRE.MatchString(d.Digest) {
		return newErr(KindMismatch, ref.Host, "unsupported digest %q", d.Digest)
	}
	if d.Size > maxBytes {
		return newErr(KindTooLarge, ref.Host, "blob %s is %d bytes, over the %d byte limit", d.Digest, d.Size, maxBytes)
	}
	h := sha256.New()
	cw := &countWriter{}
	if err := c.getTo(ctx, ref, "/blobs/"+d.Digest, "", maxBytes, c.cfg.LayerTimeout, io.MultiWriter(w, h, cw)); err != nil {
		return err
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != d.Digest {
		return newErr(KindTransient, ref.Host, "content digest mismatch: asked for %s, got %s", d.Digest, got)
	}
	if cw.n != d.Size {
		return newErr(KindTransient, ref.Host, "blob %s is %d bytes, manifest says %d", d.Digest, cw.n, d.Size)
	}
	return nil
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }
