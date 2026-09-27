package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pippinmole/upkeep.sh/agent/internal/transport"
)

func TestSaveCredentialsAtomic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	path := filepath.Join(dir, "credentials.json")

	if _, ok := loadCredentials(path); ok {
		t.Fatal("missing file loaded")
	}
	for _, c := range []storedCredentials{{"agent-1", "s0"}, {"agent-1", "s1"}} {
		if err := saveCredentials(path, c); err != nil {
			t.Fatal(err)
		}
		got, ok := loadCredentials(path)
		if !ok || got != c {
			t.Fatalf("load = %+v %v, want %+v", got, ok, c)
		}
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, %v; want 0600", st.Mode().Perm(), err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("leftover files: %v", entries)
	}
}

func TestLoadCredentialsRejectsIncomplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	for _, body := range []string{`{`, `{"agent_id":"a"}`, `{"agent_secret":"s"}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok := loadCredentials(path); ok {
			t.Errorf("%s loaded", body)
		}
	}
}

// rotateServer answers /v1/agent/rotate for agent-1 authenticated with s0.
func rotateServer(t *testing.T, calls *int) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/agent/rotate" ||
			r.Header.Get("X-Agent-ID") != "agent-1" || r.Header.Get("Authorization") != "Bearer s0" {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"agent_id": "agent-1", "agent_secret": "s1"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRotateCredentialsPersistsBeforeUse(t *testing.T) {
	var calls int
	srv := rotateServer(t, &calls)
	path := filepath.Join(t.TempDir(), "credentials.json")
	cur := storedCredentials{"agent-1", "s0"}
	if err := saveCredentials(path, cur); err != nil {
		t.Fatal(err)
	}

	next, err := rotateCredentials(transport.New(srv.URL), path, cur)
	if err != nil || next != (storedCredentials{"agent-1", "s1"}) {
		t.Fatalf("rotate = %+v, %v", next, err)
	}
	if got, _ := loadCredentials(path); got != next {
		t.Errorf("on disk = %+v, want %+v", got, next)
	}

	// Refused by the server (e.g. revoked): nothing changes.
	if got, err := rotateCredentials(transport.New(srv.URL), path, next); err == nil || got != next {
		t.Errorf("refused rotate = %+v, %v", got, err)
	}
	if got, _ := loadCredentials(path); got != next {
		t.Errorf("on disk after refused rotate = %+v", got)
	}
}

// If the new secret can't be persisted it is discarded: the agent keeps
// using the old one (valid server-side for the grace window) and retries.
func TestRotateCredentialsKeepsOldWhenPersistFails(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-writable directory")
	}
	var calls int
	srv := rotateServer(t, &calls)
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	cur := storedCredentials{"agent-1", "s0"}
	if err := saveCredentials(path, cur); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	got, err := rotateCredentials(transport.New(srv.URL), path, cur)
	if err == nil || got != cur || calls != 1 {
		t.Fatalf("rotate with read-only dir = %+v, %v (calls %d)", got, err, calls)
	}
	if onDisk, _ := loadCredentials(path); onDisk != cur {
		t.Errorf("on disk = %+v, want the old credentials", onDisk)
	}
}
