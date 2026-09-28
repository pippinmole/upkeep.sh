package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
)

const testDigest = "sha256:d74eeac9a635390a49bc21bd49fccd973de707e2a53a76ac49b552b8712ec46f"

func TestParseRepoDigest(t *testing.T) {
	for in, want := range map[string]Ref{
		"postgres@" + testDigest:                        {"docker.io", "registry-1.docker.io", "library/postgres", testDigest},
		"postgres:17@" + testDigest:                     {"docker.io", "registry-1.docker.io", "library/postgres", testDigest},
		"docker.io/library/postgres@" + testDigest:      {"docker.io", "registry-1.docker.io", "library/postgres", testDigest},
		"index.docker.io/grafana/grafana@" + testDigest: {"docker.io", "registry-1.docker.io", "grafana/grafana", testDigest},
		"grafana/grafana@" + testDigest:                 {"docker.io", "registry-1.docker.io", "grafana/grafana", testDigest},
		"ghcr.io/org/img@" + testDigest:                 {"ghcr.io", "ghcr.io", "org/img", testDigest},
		"ghcr.io/org/team/img:v1@" + testDigest:         {"ghcr.io", "ghcr.io", "org/team/img", testDigest},
		"localhost:5000/x@" + testDigest:                {"localhost:5000", "localhost:5000", "x", testDigest},
		"localhost/x@" + testDigest:                     {"localhost", "localhost", "x", testDigest},
		"10.0.0.5:5000/a/b@" + testDigest:               {"10.0.0.5:5000", "10.0.0.5:5000", "a/b", testDigest},
	} {
		got, err := ParseRepoDigest(in)
		if err != nil || got != want {
			t.Errorf("ParseRepoDigest(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"postgres",            // no digest
		"postgres@sha256:abc", // short digest
		"postgres@sha512:" + strings.Repeat("a", 128),
		"Postgres@" + testDigest,       // upper case repository
		"ghcr.io/../x@" + testDigest,   // path traversal
		"ghcr.io/a?b@" + testDigest,    // query in the path
		"exa mple.com/x@" + testDigest, // bad domain
	} {
		if r, err := ParseRepoDigest(bad); err == nil {
			t.Errorf("ParseRepoDigest(%q) = %+v, want error", bad, r)
		}
	}
}

func TestParseChallenge(t *testing.T) {
	s, p := parseChallenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/postgres:pull,push"`)
	if s != "bearer" || p["realm"] != "https://auth.docker.io/token" || p["service"] != "registry.docker.io" ||
		p["scope"] != "repository:library/postgres:pull,push" {
		t.Errorf("got %q %v", s, p)
	}
	if s, p := parseChallenge(`Basic realm="Registry"`); s != "basic" || p["realm"] != "Registry" {
		t.Errorf("got %q %v", s, p)
	}
}

// index -> platform manifest -> attestation manifest -> SPDX statement,
// through the token flow and a blob redirect to another origin.
func TestFetchSBOMAttestation(t *testing.T) {
	f := newFakeRegistry(t, "library/postgres")
	doc := spdxPredicate(t)
	im := f.pushImage(map[string][]byte{
		"https://spdx.dev/Document": doc,
		"https://cyclonedx.org/bom": cdxPredicate,
	})
	c := f.client(Config{})
	ctx := context.Background()

	// containerd store: image id = index digest.
	s, err := c.FetchSBOM(ctx, f.ref(im.index), Platform{OS: "linux", Architecture: "amd64"}, im.index.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if s.Format != FormatSPDX || s.Via != ViaAttestationManifest || s.ManifestDigest != im.amd64.Digest {
		t.Errorf("sbom = %s via %s for %s", s.Format, s.Via, s.ManifestDigest)
	}
	var got, want any
	_ = json.Unmarshal(s.Document, &got)
	_ = json.Unmarshal(doc, &want)
	if !reflect.DeepEqual(got, want) {
		t.Error("document differs from the predicate")
	}
	if len(f.tokenScopes) != 1 || f.tokenScopes[0] != "repository:library/postgres:pull" {
		t.Errorf("token scopes = %v", f.tokenScopes)
	}
	for _, a := range f.cdnAuth {
		if a != "" {
			t.Errorf("registry token sent to the CDN: %q", a)
		}
	}
	if len(f.cdnAuth) != 1 {
		t.Errorf("%d blob fetches, want 1 (SPDX only)", len(f.cdnAuth))
	}

	// Classic store: image id = config digest (one more manifest GET).
	if _, err := c.FetchSBOM(ctx, f.ref(im.index), Platform{OS: "linux", Architecture: "amd64"}, im.config.Digest); err != nil {
		t.Fatal(err)
	}
	// An id that is none of the image's digests is refused.
	_, err = c.FetchSBOM(ctx, f.ref(im.index), Platform{OS: "linux", Architecture: "amd64"}, testDigest)
	if KindOf(err) != KindMismatch {
		t.Errorf("foreign image id: %v, want mismatch", err)
	}
	// A platform the index doesn't have.
	_, err = c.FetchSBOM(ctx, f.ref(im.index), Platform{OS: "linux", Architecture: "s390x"}, im.index.Digest)
	if KindOf(err) != KindMismatch {
		t.Errorf("missing platform: %v, want mismatch", err)
	}
	// arm64 matches v8 either way, but has no attestation (and no referrers).
	_, err = c.FetchSBOM(ctx, f.ref(im.index), Platform{OS: "linux", Architecture: "arm64"}, im.index.Digest)
	if KindOf(err) != KindNoAttestation {
		t.Errorf("arm64: %v, want no attestation", err)
	}
}

func TestFetchSBOMCycloneDXOnly(t *testing.T) {
	f := newFakeRegistry(t, "org/app")
	im := f.pushImage(map[string][]byte{"https://cyclonedx.org/bom/v1.6": cdxPredicate})
	s, err := f.client(Config{}).FetchSBOM(context.Background(), f.ref(im.index),
		Platform{OS: "linux", Architecture: "amd64"}, im.index.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if s.Format != FormatCycloneDX || !bytes.Equal(s.Document, cdxPredicate) {
		t.Errorf("sbom = %s %s", s.Format, s.Document)
	}
}

// OCI 1.1 referrers: no attestation manifest, an SPDX artifact referring
// to the platform manifest; the image pulled by its manifest digest.
func TestFetchSBOMReferrers(t *testing.T) {
	f := newFakeRegistry(t, "org/app")
	im := f.pushImage(nil)
	doc := spdxPredicate(t)
	layer := f.addBlob(doc, "application/spdx+json")
	emptyCfg := f.addBlob([]byte(`{}`), "application/vnd.oci.empty.v1+json")
	art := f.addManifest(map[string]any{"schemaVersion": 2, "mediaType": MediaTypeOCIManifest,
		"artifactType": "application/spdx+json", "config": emptyCfg, "layers": []any{layer},
		"subject": im.amd64}, MediaTypeOCIManifest)
	art.ArtifactType = "application/spdx+json"
	sig := Descriptor{MediaType: MediaTypeOCIManifest, ArtifactType: "application/vnd.dev.cosign.artifact.sig.v1+json",
		Digest: testDigest, Size: 10}
	f.referrers[im.amd64.Digest] = mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": MediaTypeOCIIndex,
		"manifests": []any{sig, art}})

	s, err := f.client(Config{}).FetchSBOM(context.Background(), f.ref(im.amd64),
		Platform{OS: "linux", Architecture: "amd64"}, im.amd64.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if s.Format != FormatSPDX || s.Via != ViaReferrers || !bytes.Equal(s.Document, doc) {
		t.Errorf("sbom = %s via %s", s.Format, s.Via)
	}
}

func TestFetchSBOMNoAttestation(t *testing.T) {
	f := newFakeRegistry(t, "org/app")
	im := f.pushImage(nil)
	_, err := f.client(Config{}).FetchSBOM(context.Background(), f.ref(im.index),
		Platform{OS: "linux", Architecture: "amd64"}, im.index.Digest)
	if KindOf(err) != KindNoAttestation {
		t.Fatalf("got %v, want no attestation", err)
	}
}

func TestFetchSBOMDigestMismatch(t *testing.T) {
	f := newFakeRegistry(t, "org/app")
	im := f.pushImage(map[string][]byte{"https://spdx.dev/Document": spdxPredicate(t)})
	ctx, p := context.Background(), Platform{OS: "linux", Architecture: "amd64"}

	f.tamper[im.index.Digest] = true
	_, err := f.client(Config{}).FetchSBOM(ctx, f.ref(im.index), p, im.index.Digest)
	if KindOf(err) != KindTransient || !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("tampered index: %v", err)
	}
	f.tamper = map[string]bool{}
	for d := range f.blobs {
		f.tamper[d] = true // every blob, served by the CDN
	}
	_, err = f.client(Config{}).FetchSBOM(ctx, f.ref(im.index), p, im.index.Digest)
	if KindOf(err) != KindTransient || !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("tampered blob: %v", err)
	}
}

func TestFetchSBOMSizeCap(t *testing.T) {
	f := newFakeRegistry(t, "org/app")
	im := f.pushImage(map[string][]byte{"https://spdx.dev/Document": spdxPredicate(t)})
	ctx, p := context.Background(), Platform{OS: "linux", Architecture: "amd64"}
	_, err := f.client(Config{MaxBlobBytes: 1024}).FetchSBOM(ctx, f.ref(im.index), p, im.index.Digest)
	if KindOf(err) != KindTooLarge {
		t.Errorf("blob cap: %v, want too large", err)
	}
	_, err = f.client(Config{MaxManifestBytes: 64}).FetchSBOM(ctx, f.ref(im.index), p, im.index.Digest)
	if KindOf(err) != KindTooLarge {
		t.Errorf("manifest cap: %v, want too large", err)
	}
}

// A 429 backs the registry off for Retry-After; requests in the meantime
// fail fast without reaching it.
func TestFetchSBOMRateLimited(t *testing.T) {
	f := newFakeRegistry(t, "org/app")
	im := f.pushImage(map[string][]byte{"https://spdx.dev/Document": spdxPredicate(t)})
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	c := f.client(Config{Now: func() time.Time { return now }})
	ctx, p := context.Background(), Platform{OS: "linux", Architecture: "amd64"}

	f.status["manifests/"+im.index.Digest] = http.StatusTooManyRequests
	f.header.Set("Retry-After", "120")
	_, err := c.FetchSBOM(ctx, f.ref(im.index), p, im.index.Digest)
	if KindOf(err) != KindRateLimited || !RetryAt(err).Equal(now.Add(2*time.Minute)) {
		t.Fatalf("got %v (retry at %v), want rate limited until +2m", err, RetryAt(err))
	}
	before := f.requests.Load()
	delete(f.status, "manifests/"+im.index.Digest)
	_, err = c.FetchSBOM(ctx, f.ref(im.index), p, im.index.Digest)
	if KindOf(err) != KindRateLimited || f.requests.Load() != before {
		t.Fatalf("during backoff: %v, %d requests", err, f.requests.Load()-before)
	}
	now = now.Add(3 * time.Minute)
	if _, err := c.FetchSBOM(ctx, f.ref(im.index), p, im.index.Digest); err != nil {
		t.Fatalf("after backoff: %v", err)
	}
}

func TestFetchSBOMDenied(t *testing.T) {
	f := newFakeRegistry(t, "org/private")
	im := f.pushImage(nil)
	ctx, p := context.Background(), Platform{OS: "linux", Architecture: "amd64"}

	// The default guard refuses the loopback registry before connecting.
	strict := f.client(Config{Guard: &netguard.Guard{}})
	_, err := strict.FetchSBOM(ctx, f.ref(im.index), p, im.index.Digest)
	if KindOf(err) != KindDenied || f.requests.Load() != 0 {
		t.Errorf("netguard: %v, %d requests", err, f.requests.Load())
	}

	for code, header := range map[int]string{
		http.StatusNotFound:     "",
		http.StatusForbidden:    "",
		http.StatusUnauthorized: `Basic realm="private"`,
	} {
		f.status = map[string]int{"manifests/" + im.index.Digest: code}
		f.header = http.Header{}
		if header != "" {
			f.header.Set("WWW-Authenticate", header)
		}
		_, err := f.client(Config{}).FetchSBOM(ctx, f.ref(im.index), p, im.index.Digest)
		if KindOf(err) != KindDenied {
			t.Errorf("%d: %v, want denied", code, err)
		}
	}

	// A token for the repository, but the manifest still 401s: private.
	f.status = map[string]int{}
	delete(f.manifests, im.index.Digest)
	_, err = f.client(Config{}).FetchSBOM(ctx, f.ref(im.index), p, im.index.Digest)
	if KindOf(err) != KindDenied {
		t.Errorf("unknown manifest: %v, want denied", err)
	}
}

// Docker Hub credentials go only to Docker Hub's token endpoint.
func TestDockerHubCredentialsScoped(t *testing.T) {
	f := newFakeRegistry(t, "org/app")
	im := f.pushImage(map[string][]byte{"https://spdx.dev/Document": spdxPredicate(t)})
	c := f.client(Config{DockerHubUsername: "u", DockerHubToken: "dckr_pat_x"})
	if _, err := c.FetchSBOM(context.Background(), f.ref(im.index), Platform{OS: "linux", Architecture: "amd64"}, im.index.Digest); err != nil {
		t.Fatal(err)
	}
	for _, a := range f.tokenAuth {
		if a != "" {
			t.Errorf("credentials sent to a non-Docker Hub token endpoint: %q", a)
		}
	}
}
