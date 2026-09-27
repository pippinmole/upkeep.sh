package transport

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
)

func TestPushSnapshotRotateSignal(t *testing.T) {
	signal := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/snapshots" || r.Header.Get("X-Agent-ID") != "a" || r.Header.Get("Authorization") != "Bearer s" {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		if signal {
			w.Header().Set(RotateHeader, "1")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	c := New(srv.URL)

	res, err := c.PushSnapshot("a", "s", collector.Snapshot{})
	if err != nil || res.RotateCredentials {
		t.Errorf("no signal: %+v, %v", res, err)
	}
	signal = true
	res, err = c.PushSnapshot("a", "s", collector.Snapshot{})
	if err != nil || !res.RotateCredentials {
		t.Errorf("signal: %+v, %v", res, err)
	}
	if _, err := c.PushSnapshot("a", "wrong", collector.Snapshot{}); err == nil {
		t.Error("401 not reported")
	}
}

func TestRotateCredentialsRejectsMismatchedAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"agent_id":"someone-else","agent_secret":"x"}`))
	}))
	defer srv.Close()
	if _, err := New(srv.URL).RotateCredentials("a", "s"); err == nil {
		t.Error("accepted a response for another agent")
	}
}
