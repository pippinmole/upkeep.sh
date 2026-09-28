package registry

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
)

// fakeRegistry is an OCI registry over TLS with the anonymous token flow,
// serving blobs through a redirect to a second server (the "CDN"), as
// Docker Hub does.
type fakeRegistry struct {
	t        *testing.T
	srv, cdn *httptest.Server
	repo     string

	mu        sync.Mutex
	manifests map[string][]byte
	types     map[string]string
	blobs     map[string][]byte
	referrers map[string][]byte // manifest digest -> referrers index; absent = 404
	tamper    map[string]bool   // serve these digests with altered content
	status    map[string]int    // path suffix -> forced status
	header    http.Header       // extra headers on forced statuses

	requests    atomic.Int32 // to the registry (not the CDN)
	tokenScopes []string
	tokenAuth   []string // Authorization sent to the token endpoint
	cdnAuth     []string // Authorization sent to the CDN (must be empty)
}

func newFakeRegistry(t *testing.T, repo string) *fakeRegistry {
	f := &fakeRegistry{t: t, repo: repo, manifests: map[string][]byte{}, types: map[string]string{},
		blobs: map[string][]byte{}, referrers: map[string][]byte{}, tamper: map[string]bool{},
		status: map[string]int{}, header: http.Header{}}
	f.cdn = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.cdnAuth = append(f.cdnAuth, r.Header.Get("Authorization"))
		b, ok := f.blobs[strings.TrimPrefix(r.URL.Path, "/blob/")]
		tamper := f.tamper[strings.TrimPrefix(r.URL.Path, "/blob/")]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		if tamper {
			b = append([]byte("x"), b...)
		}
		_, _ = w.Write(b)
	}))
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(func() { f.srv.Close(); f.cdn.Close() })
	return f
}

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/token" {
		f.tokenScopes = append(f.tokenScopes, r.URL.Query().Get("scope"))
		f.tokenAuth = append(f.tokenAuth, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "tok-1", "expires_in": 300})
		return
	}
	prefix := "/v2/" + f.repo + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	for suffix, code := range f.status {
		if strings.HasSuffix(rest, suffix) {
			for k, v := range f.header {
				w.Header()[k] = v
			}
			w.WriteHeader(code)
			return
		}
	}
	if r.Header.Get("Authorization") != "Bearer tok-1" {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="`+f.srv.URL+`/token",service="fake",scope="repository:`+f.repo+`:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	kind, digest, _ := strings.Cut(rest, "/")
	switch kind {
	case "manifests":
		b, ok := f.manifests[digest]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if f.tamper[digest] {
			b = append([]byte(" "), b...)
		}
		w.Header().Set("Content-Type", f.types[digest])
		_, _ = w.Write(b)
	case "blobs":
		http.Redirect(w, r, f.cdn.URL+"/blob/"+digest, http.StatusTemporaryRedirect)
	case "referrers":
		b, ok := f.referrers[digest]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", MediaTypeOCIIndex)
		_, _ = w.Write(b)
	default:
		http.NotFound(w, r)
	}
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func mustJSON(t *testing.T, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fakeRegistry) addManifest(v any, mediaType string) Descriptor {
	b := mustJSON(f.t, v)
	d := digestOf(b)
	f.mu.Lock()
	f.manifests[d], f.types[d] = b, mediaType
	f.mu.Unlock()
	return Descriptor{MediaType: mediaType, Digest: d, Size: int64(len(b))}
}

func (f *fakeRegistry) addBlob(b []byte, mediaType string) Descriptor {
	d := digestOf(b)
	f.mu.Lock()
	f.blobs[d] = b
	f.mu.Unlock()
	return Descriptor{MediaType: mediaType, Digest: d, Size: int64(len(b))}
}

// ref is the repo digest of desc on this registry.
func (f *fakeRegistry) ref(desc Descriptor) Ref {
	r, err := ParseRepoDigest(strings.TrimPrefix(f.srv.URL, "https://") + "/" + f.repo + "@" + desc.Digest)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// client trusts the test servers' certificate and allows loopback (the
// test registry is on 127.0.0.1).
func (f *fakeRegistry) client(cfg Config) *Client {
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	if cfg.Guard == nil {
		cfg.Guard = &netguard.Guard{AllowPrivate: true}
	}
	cfg.Guard.TLSConfig = &tls.Config{RootCAs: pool}
	return New(cfg)
}

// makeStatement wraps an SBOM predicate in an in-toto statement about subject.
func makeStatement(t *testing.T, predicateType string, predicate []byte, subject string) []byte {
	return mustJSON(t, map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": predicateType,
		"subject":       []any{map[string]any{"name": "pkg:docker/x", "digest": map[string]string{"sha256": strings.TrimPrefix(subject, "sha256:")}}},
		"predicate":     json.RawMessage(predicate),
	})
}

// spdxPredicate is the real postgres:17 linux/amd64 SPDX document from
// Docker Hub (trimmed; see internal/sbom/testdata).
func spdxPredicate(t *testing.T) []byte {
	b, err := os.ReadFile("../sbom/testdata/postgres17-amd64.spdx.intoto.json")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	return st.Predicate
}

var cdxPredicate = []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"express","version":"4.21.2","purl":"pkg:npm/express@4.21.2"}]}`)

// testImage is a two-platform image: its index, amd64 manifest and config.
type testImage struct {
	index, amd64, arm64, config Descriptor
}

// pushImage pushes a linux/amd64 + linux/arm64/v8 image, with a BuildKit
// attestation manifest for amd64 holding the given predicates (type ->
// document) plus a provenance one; none when predicates is nil.
func (f *fakeRegistry) pushImage(predicates map[string][]byte) testImage {
	var im testImage
	im.config = f.addBlob([]byte(`{"architecture":"amd64","os":"linux"}`), "application/vnd.oci.image.config.v1+json")
	im.amd64 = f.addManifest(map[string]any{"schemaVersion": 2, "mediaType": MediaTypeOCIManifest,
		"config": im.config, "layers": []any{}}, MediaTypeOCIManifest)
	armCfg := f.addBlob([]byte(`{"architecture":"arm64","os":"linux"}`), "application/vnd.oci.image.config.v1+json")
	im.arm64 = f.addManifest(map[string]any{"schemaVersion": 2, "mediaType": MediaTypeOCIManifest,
		"config": armCfg, "layers": []any{}}, MediaTypeOCIManifest)
	amd, arm := im.amd64, im.arm64
	amd.Platform = &Platform{OS: "linux", Architecture: "amd64"}
	arm.Platform = &Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	entries := []Descriptor{amd, arm}
	if predicates != nil {
		layers := []Descriptor{}
		prov := f.addBlob(makeStatement(f.t, "https://slsa.dev/provenance/v0.2", []byte(`{}`), im.amd64.Digest), mediaTypeInToto)
		prov.Annotations = map[string]string{annotationPredicate: "https://slsa.dev/provenance/v0.2"}
		layers = append(layers, prov)
		for pt, doc := range predicates {
			l := f.addBlob(makeStatement(f.t, pt, doc, im.amd64.Digest), mediaTypeInToto)
			l.Annotations = map[string]string{annotationPredicate: pt}
			layers = append(layers, l)
		}
		attCfg := f.addBlob([]byte(`{}`), "application/vnd.oci.image.config.v1+json")
		att := f.addManifest(map[string]any{"schemaVersion": 2, "mediaType": MediaTypeOCIManifest,
			"config": attCfg, "layers": layers}, MediaTypeOCIManifest)
		att.Platform = &Platform{OS: "unknown", Architecture: "unknown"}
		att.Annotations = map[string]string{annotationRefType: refTypeAttestation, annotationRefDigest: im.amd64.Digest}
		entries = append(entries, att)
	}
	im.index = f.addManifest(map[string]any{"schemaVersion": 2, "mediaType": MediaTypeOCIIndex, "manifests": entries},
		MediaTypeOCIIndex)
	return im
}
