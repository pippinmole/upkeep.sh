package dockerapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckAPIVersion(t *testing.T) {
	for v, ok := range map[string]bool{
		"1.41": true, "1.47": true, "1.56": true, "1.100": true, "2.0": true,
		"1.40": false, "1.24": false, "1.4": false, "": false,
	} {
		if err := CheckAPIVersion(v); (err == nil) != ok {
			t.Errorf("CheckAPIVersion(%q) = %v, want ok=%v", v, err, ok)
		}
	}
}

func TestOpenSocketNotMounted(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	_, err := Open(ctx, filepath.Join(dir, "docker.sock"))
	if !errors.Is(err, ErrSocketNotMounted) {
		t.Errorf("missing path: %v, want ErrSocketNotMounted", err)
	}

	// A bind mount of a missing host path shows up as an empty directory.
	sub := filepath.Join(dir, "sub.sock")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, sub); !errors.Is(err, ErrSocketNotMounted) {
		t.Errorf("directory: %v, want ErrSocketNotMounted", err)
	}

	// Something is there but nothing answers: an error, not "not mounted".
	file := filepath.Join(dir, "file.sock")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := Open(ctx, file); err == nil || errors.Is(err, ErrSocketNotMounted) {
		t.Errorf("unreachable: %v, want a non-ErrSocketNotMounted error", err)
	}
}

// fakeEngine serves /_ping reporting apiVersion and /v<apiVersion>/version
// on a unix socket in a temp dir, and returns the socket path.
func fakeEngine(t *testing.T, apiVersion string) string {
	t.Helper()
	// Short dir: unix socket paths are limited to ~104-108 bytes.
	dir, err := os.MkdirTemp("", "dapi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Api-Version", apiVersion)
		w.Header().Set("Ostype", "linux")
		w.Header().Set("Swarm", "active/manager")
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/v"+apiVersion+"/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Version":"29.8.0","ApiVersion":"` + apiVersion + `","Os":"linux","Arch":"amd64"}`))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return path
}

func TestOpenNegotiates(t *testing.T) {
	path := fakeEngine(t, "1.47")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	p, err := e.Ping(ctx)
	if err != nil || p.APIVersion != "1.47" || p.SwarmStatus == nil || !p.SwarmStatus.ControlAvailable {
		t.Errorf("Ping = %+v, %v", p, err)
	}
	// Only /v1.47/version is served: this fails unless the client
	// downgraded from its own maximum to the engine's version.
	v, err := e.Version(ctx)
	if err != nil || v.Version != "29.8.0" || v.APIVersion != "1.47" {
		t.Errorf("Version = %+v, %v", v, err)
	}
}

func TestOpenRejectsOldEngine(t *testing.T) {
	// 1.40 passes the moby client's own minimum but not ours; 1.30 fails
	// both and must still get our message.
	for _, v := range []string{"1.40", "1.30"} {
		path := fakeEngine(t, v)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := Open(ctx, path)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "too old") || errors.Is(err, ErrSocketNotMounted) {
			t.Errorf("API %s: %v, want a too-old error", v, err)
		}
	}
}
