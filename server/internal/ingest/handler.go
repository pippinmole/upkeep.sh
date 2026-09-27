package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/pippinmole/upkeep.sh/server/internal/authn"
	"github.com/pippinmole/upkeep.sh/server/internal/jobs"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

type Handler struct {
	Store *store.Store
	// Jobs is an insert-only River client. Snapshot ingest enqueues the
	// matcher/findings jobs a push implies inside its own transaction.
	// nil disables enqueueing (tests); the worker's matcher_sweep then
	// still evaluates new versions, but findings are not reconciled.
	Jobs *river.Client[pgx.Tx]
}

type enrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	// Version and Platform describe the agent build (optional; older
	// agents omit them and report them later in the push's agent block).
	Version  string `json:"version"`
	Platform string `json:"platform"`
}

type enrollResponse struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
}

// Enroll exchanges a one-time dashboard-generated token for a durable
// agent_id + secret. It creates an agent, not a host: the host is created
// (or re-attached by identity) on the agent's first push. The token is
// consumed in the same transaction, so it cannot be replayed even if leaked
// after use.
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

	secret, hash, err := authn.GenerateSecret()
	if err != nil {
		log.Printf("generate secret: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	agentID, err := h.Store.EnrollAgent(r.Context(), store.EnrollInput{
		Token:      req.EnrollmentToken,
		Hostname:   clip(req.Hostname, 255),
		Version:    clip(req.Version, 64),
		Platform:   clip(req.Platform, 64),
		SecretHash: hash,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "invalid or expired enrollment token", http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("enroll agent: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("agent %s enrolled", agentID)
	writeJSON(w, http.StatusOK, enrollResponse{AgentID: agentID, AgentSecret: secret})
}

// Snapshot ingests a fact push from an enrolled agent. Auth is a bearer
// secret scoped to one agent id (X-Agent-ID), verified against a stored
// hash — never a shared platform-wide credential. The host the push
// describes is resolved from its host block (store.resolveHost).
func (h *Handler) Snapshot(w http.ResponseWriter, r *http.Request) {
	agentID := r.Header.Get("X-Agent-ID")
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if agentID == "" || secret == "" {
		http.Error(w, "missing credentials", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	cred, err := h.Store.AgentCredential(ctx, agentID)
	if err != nil || !authn.VerifySecret(secret, cred.SecretHash) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if cred.Revoked {
		http.Error(w, "agent revoked", http.StatusUnauthorized)
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

	in := buildSnapshotInput(payload, agentID, collectedAt, time.Now().UTC(), clientIP(r))
	// Vulnerability matching and findings run on the worker, never inline:
	// the jobs are inserted in the snapshot transaction (River InsertTx),
	// so they exist if and only if the snapshot committed.
	if h.Jobs != nil {
		in.AfterWrite = func(ctx context.Context, tx pgx.Tx, res store.SnapshotResult) error {
			return jobs.EnqueueAfterIngest(ctx, h.Jobs, tx, res.HostID, res)
		}
	}

	res, err := h.Store.InsertSnapshot(ctx, in)
	if errors.Is(err, store.ErrUnknownHostRef) {
		http.Error(w, "unknown host ref", http.StatusUnprocessableEntity)
		return
	} else if errors.Is(err, store.ErrAgentNotFound) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("agent %s: insert snapshot: %v", agentID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hostID := res.HostID
	switch {
	case res.Host.Reattached:
		log.Printf("agent %s: re-attached to existing host %s by machine-id", agentID, hostID)
	case res.Host.Created && res.Host.DuplicateOf != "":
		log.Printf("agent %s: created host %s, flagged possible duplicate of %s (machine-id collected by another active agent)",
			agentID, hostID, res.Host.DuplicateOf)
	case res.Host.Created:
		log.Printf("agent %s: created host %s", agentID, hostID)
	case res.Host.DuplicateOf != "":
		log.Printf("agent %s: host %s flagged possible duplicate of %s (same machine-id)", agentID, hostID, res.Host.DuplicateOf)
	}
	for _, inv := range res.Inventory {
		if inv.Outcome != store.InventoryUnchanged {
			log.Printf("host %s: %s inventory %s (+%d -%d, %d new versions, %d source resets)",
				hostID, inv.Ecosystem, inv.Outcome, inv.Added, inv.Removed, len(inv.NewSoftwareIDs), len(inv.ResetSoftwareIDs))
		}
	}
	for _, f := range res.Facts {
		if f.Opened+f.Closed > 0 {
			log.Printf("host %s: %s changed (+%d -%d ranges)", hostID, f.Kind, f.Opened, f.Closed)
		}
	}
	if res.KernelChanged {
		log.Printf("host %s: running kernel now %q", hostID, in.KernelRelease)
	}

	// TODO(phase 1, exposure): enqueue the external port-exposure check
	// here (same AfterWrite/InsertTx pattern) once that worker exists.

	w.WriteHeader(http.StatusAccepted)
}

// buildSnapshotInput maps a decoded payload onto the store input, including
// the inventory plan (which ecosystems are authoritative this push).
func buildSnapshotInput(payload SnapshotPayload, agentID string, collectedAt, now time.Time, sourceIP string) store.SnapshotInput {
	// Range boundaries use collected_at (agent clock), but never a time in
	// the server's future: a push from a host whose clock runs ahead would
	// otherwise make every later, correctly-timed push look stale.
	inventoryAt := collectedAt
	if inventoryAt.After(now) {
		inventoryAt = now
	}

	in := store.SnapshotInput{
		AgentID:        agentID,
		Agent:          agentReport(payload),
		Host:           hostClaim(payload),
		OSFamily:       osFamily(payload),
		OSKnown:        payload.OS.ID != "" && collectorOK(payload, CollectorOS),
		SchemaVersion:  payload.SchemaVersion,
		CollectedAt:    collectedAt,
		OSID:           payload.OS.ID,
		OSVersionID:    payload.OS.VersionID,
		OSCodename:     payload.OS.Codename,
		KernelRelease:  kernelRelease(payload),
		RebootRequired: payload.RebootRequired,
		RebootPackages: payload.RebootPackages,
		SourceIP:       sourceIP,
		PublicIPv4:     payload.PublicIPv4,
		PublicIPv6:     payload.PublicIPv6,
		InventoryAt:    inventoryAt,
	}
	if payload.Collectors != nil {
		if b, err := json.Marshal(payload.Collectors); err == nil {
			in.CollectorStatus = b
		}
	}
	for _, s := range payload.ListeningSockets {
		in.ListeningSockets = append(in.ListeningSockets, store.SocketInput{
			Proto: s.Proto, LocalAddr: s.LocalAddr, Port: s.Port, PID: s.PID, ProcessName: s.ProcessName,
		})
	}

	sets, skipped := planInventory(payload)
	in.Inventory = sets
	for _, sk := range skipped {
		log.Printf("agent %s: %s inventory not diffed: %s", agentID, sk.Ecosystem, sk.Reason)
	}

	factSets, notes := planFacts(payload)
	in.FactSets = factSets
	for _, n := range notes {
		log.Printf("agent %s: %s", agentID, n)
	}
	in.UptimeSeconds = uptimeSeconds(payload)
	in.Arch = hostArch(payload)
	facts, err := linuxFacts(payload, in.OSFamily)
	if err != nil {
		log.Printf("agent %s: facts block dropped: %v", agentID, err)
	}
	in.Facts = facts
	return in
}

// collectorOK reports whether a collector succeeded. Payloads without a
// collectors map predate per-collector status; their sections are all
// authoritative.
func collectorOK(p SnapshotPayload, name string) bool {
	return p.Collectors == nil || p.Collectors[name].Status == CollectorStatusOK
}

// hostClaim maps the host block onto the store's claim. No host block
// (older agents) means the agent's local host with no identity. The
// machine-id is used only when the host_identity collector succeeded (or
// the payload has no collectors map). The hostname is kept even when that
// collector failed: the agent reads it independently of the machine-id,
// and a missing machine-id is exactly what fails it on images without one.
func hostClaim(p SnapshotPayload) store.HostClaim {
	if p.Host == nil {
		return store.HostClaim{Ref: store.LocalRef}
	}
	c := store.HostClaim{
		Ref:       strings.TrimSpace(p.Host.Ref),
		MachineID: sanitizeIdentity(p.Host.Identity.MachineID),
		Hostname:  clip(strings.TrimSpace(p.Host.Hostname), 255),
	}
	if c.Ref == "" {
		c.Ref = store.LocalRef
	}
	if !collectorOK(p, CollectorHostIdentity) {
		c.MachineID = ""
	}
	return c
}

// sanitizeIdentity rejects identity values that are empty or can't be a
// machine identifier ("uninitialized", control characters, absurd length).
func sanitizeIdentity(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "uninitialized" || len(v) > 128 || strings.ContainsAny(v, "\x00\n\t ") {
		return ""
	}
	return strings.ToLower(v)
}

// osFamily returns host.os_family when it is a known family and the os
// collector succeeded. Agents that predate the host block only ever ran on
// Linux, so an OS id without a host block means Linux.
func osFamily(p SnapshotPayload) string {
	if p.Host == nil {
		if p.OS.ID != "" {
			return "linux"
		}
		return ""
	}
	if !collectorOK(p, CollectorOS) {
		return ""
	}
	switch f := p.Host.OSFamily; f {
	case "linux", "windows", "macos":
		return f
	}
	return ""
}

func agentReport(p SnapshotPayload) store.AgentReport {
	if p.Agent == nil {
		return store.AgentReport{}
	}
	r := store.AgentReport{Version: clip(p.Agent.Version, 64), Platform: clip(p.Agent.Platform, 64)}
	if s := p.Agent.IntervalSeconds; s > 0 && s <= 7*24*3600 {
		r.IntervalSeconds = s
	}
	return r
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// kernelRelease returns the running kernel from os.kernel, or "" when it
// can't be trusted: the kernel collector did not report ok (payloads with
// a collectors map), or the value is implausible. Payloads without a
// collectors map predate the field and never carry it.
func kernelRelease(p SnapshotPayload) string {
	k := strings.TrimSpace(p.OS.Kernel)
	if k == "" || len(k) > 256 || strings.ContainsAny(k, "\x00\n\t ") {
		return ""
	}
	if p.Collectors != nil && p.Collectors[CollectorKernel].Status != CollectorStatusOK {
		return ""
	}
	return k
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
