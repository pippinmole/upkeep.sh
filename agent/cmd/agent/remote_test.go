package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pippinmole/upkeep.sh/agent/internal/snapshot"
	"github.com/pippinmole/upkeep.sh/agent/internal/target"
	"github.com/pippinmole/upkeep.sh/agent/internal/transport"
)

func TestBackoff(t *testing.T) {
	iv := 15 * time.Minute
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	for i, w := range want {
		if got := backoff(i+1, iv); got != w {
			t.Errorf("backoff(%d) = %s, want %s", i+1, got, w)
		}
	}
	// A dev agent pushing every 30s still waits at least one poll interval.
	if got := backoff(3, 30*time.Second); got != time.Minute {
		t.Errorf("short interval: %s", got)
	}
}

// fakeServer serves /v1/agent/config and records status reports.
type fakeServer struct {
	mu      sync.Mutex
	cfg     transport.AgentConfig
	reports []transport.StatusReport
	fetches int
}

func (f *fakeServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/agent/config", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.fetches++
		etag := `"` + f.cfg.Version + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_ = json.NewEncoder(w).Encode(f.cfg)
	})
	mux.HandleFunc("POST /v1/agent/status", func(w http.ResponseWriter, r *http.Request) {
		var rep transport.StatusReport
		_ = json.NewDecoder(r.Body).Decode(&rep)
		f.mu.Lock()
		f.reports = append(f.reports, rep)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func TestRemoteRunner(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	fs := &fakeServer{cfg: transport.AgentConfig{Version: "v1", Targets: []transport.RemoteTarget{
		{Ref: "h1", Mode: "ssh", Address: "127.0.0.1", Port: closedPort, Username: "upkeep"},
		{Ref: "w1", Mode: "winrm", Address: "10.0.0.9", Port: 5986, Username: "x"},
	}}}
	srv := httptest.NewServer(fs.handler())
	defer srv.Close()

	signer, err := loadOrCreateSSHKey(filepath.Join(t.TempDir(), "ssh", "id_ed25519"), true)
	if err != nil {
		t.Fatal(err)
	}
	r := newRemoteRunner(transport.New(srv.URL), signer, snapshot.New(), 15*time.Minute)
	creds := storedCredentials{AgentID: "a", AgentSecret: "s"}
	now := time.Now()

	r.poll(creds, now)
	if len(r.targets) != 1 || r.targets["h1"] == nil {
		t.Fatalf("targets: %v (winrm must be skipped)", r.targets)
	}
	r.runDue(context.Background(), creds, now)
	if len(fs.reports) != 1 {
		t.Fatalf("reports: %d", len(fs.reports))
	}
	rep := fs.reports[0]
	if !strings.HasPrefix(rep.SSHPublicKey, "ssh-ed25519 ") || !strings.HasSuffix(rep.SSHPublicKey, " upkeep-agent") {
		t.Errorf("public key: %q", rep.SSHPublicKey)
	}
	if len(rep.Targets) != 1 || rep.Targets[0].Ref != "h1" || rep.Targets[0].ErrorCode != target.CodeUnreachable {
		t.Fatalf("report: %+v", rep.Targets)
	}
	if next := r.targets["h1"].nextAt; next.Sub(now) != time.Minute {
		t.Errorf("first retry in %s, want 1m", next.Sub(now))
	}

	// Nothing due and the key already reported: no request.
	r.runDue(context.Background(), creds, now.Add(30*time.Second))
	if len(fs.reports) != 1 {
		t.Errorf("reported with nothing due")
	}

	// Unchanged config (304) keeps the backoff; a changed target is due now.
	r.poll(creds, now.Add(30*time.Second))
	if r.targets["h1"].fails != 1 {
		t.Errorf("304 reset the target")
	}
	fs.mu.Lock()
	fs.cfg.Version = "v2"
	fs.cfg.Targets[0].Username = "monitor"
	fs.mu.Unlock()
	later := now.Add(40 * time.Second)
	r.poll(creds, later)
	if tg := r.targets["h1"]; tg.fails != 0 || !tg.nextAt.Equal(later) || tg.cfg.Username != "monitor" {
		t.Errorf("changed target not due: %+v", tg)
	}

	// Removed from the config: dropped.
	fs.mu.Lock()
	fs.cfg = transport.AgentConfig{Version: "v3"}
	fs.mu.Unlock()
	r.poll(creds, later)
	if len(r.targets) != 0 {
		t.Errorf("removed target kept: %v", r.targets)
	}
}

func TestSSHKeyPersists(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ssh", "id_ed25519")
	a, err := loadOrCreateSSHKey(p, true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadOrCreateSSHKey(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if authorizedKeyLine(a) != authorizedKeyLine(b) {
		t.Fatal("key regenerated on second load")
	}
	// An operator-supplied path is never generated.
	if _, err := loadOrCreateSSHKey(filepath.Join(t.TempDir(), "missing"), false); err == nil {
		t.Fatal("missing operator key: want error")
	}
}
