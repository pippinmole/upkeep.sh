package ingest

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/icondesk/security-whatnot/server/internal/authn"
	"github.com/icondesk/security-whatnot/server/internal/store"
)

type Handler struct {
	Store *store.Store
}

type enrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
}

type enrollResponse struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
}

// Enroll exchanges a one-time dashboard-generated token for a durable
// agent_id + secret. The token is consumed atomically so it cannot be
// replayed even if leaked after use.
func (h *Handler) Enroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.EnrollmentToken == "" {
		http.Error(w, "enrollment_token required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	userID, err := h.Store.ConsumeEnrollmentToken(ctx, req.EnrollmentToken)
	if err != nil {
		http.Error(w, "invalid or expired enrollment token", http.StatusUnauthorized)
		return
	}

	hostname := req.Hostname
	if hostname == "" {
		hostname = "unknown-host"
	}
	hostID, err := h.Store.CreateHost(ctx, userID, hostname)
	if err != nil {
		log.Printf("create host: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	secret, hash, err := authn.GenerateSecret()
	if err != nil {
		log.Printf("generate secret: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.Store.StoreAgentSecretHash(ctx, hostID, hash); err != nil {
		log.Printf("store secret: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, enrollResponse{AgentID: hostID, AgentSecret: secret})
}

// Snapshot ingests a fact push from an enrolled agent. Auth is a bearer
// secret scoped to one host id (X-Agent-ID), verified against a stored
// hash — never a shared platform-wide credential.
func (h *Handler) Snapshot(w http.ResponseWriter, r *http.Request) {
	hostID := r.Header.Get("X-Agent-ID")
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if hostID == "" || secret == "" {
		http.Error(w, "missing credentials", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	hash, err := h.Store.AgentSecretHash(ctx, hostID)
	if err != nil || !authn.VerifySecret(secret, hash) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	var payload SnapshotPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if payload.SchemaVersion < MinSupportedSchemaVersion {
		http.Error(w, "unsupported schema_version", http.StatusBadRequest)
		return
	}

	collectedAt, err := time.Parse(time.RFC3339, payload.CollectedAt)
	if err != nil {
		collectedAt = time.Now().UTC()
	}

	in := store.SnapshotInput{
		HostID:         hostID,
		CollectedAt:    collectedAt,
		OSID:           payload.OS.ID,
		OSVersionID:    payload.OS.VersionID,
		OSCodename:     payload.OS.Codename,
		RebootRequired: payload.RebootRequired,
		RebootPackages: payload.RebootPackages,
		SourceIP:       clientIP(r),
	}
	for _, p := range payload.Packages {
		in.Packages = append(in.Packages, store.PackageInput{Name: p.Name, Version: p.Version, Arch: p.Arch})
	}
	for _, s := range payload.ListeningSockets {
		in.ListeningSockets = append(in.ListeningSockets, store.SocketInput{
			Proto: s.Proto, LocalAddr: s.LocalAddr, Port: s.Port, PID: s.PID, ProcessName: s.ProcessName,
		})
	}

	if _, err := h.Store.InsertSnapshot(ctx, in); err != nil {
		log.Printf("insert snapshot: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = h.Store.TouchHostLastSeen(ctx, hostID, time.Now().UTC())

	// TODO(phase 1): enqueue vuln matching + port-exposure check for this
	// snapshot instead of doing it inline, once those workers exist.

	w.WriteHeader(http.StatusAccepted)
}

// clientIP prefers X-Forwarded-For because production deploys sit behind
// Dokploy/Coolify's Traefik proxy; this value is later used to verify that
// an external port scan only ever targets an enrolled agent's own IP, so
// the reverse proxy MUST be configured to set/overwrite this header itself
// (never trust it from a source that isn't the proxy).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
