package ingest

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/pippinmole/upkeep.sh/server/internal/sshkey"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// Remote targets (PROTOCOL.md "Remote targets"). The agent pulls its
// target list and reports connection outcomes; the server never connects
// to the agent or to the targets.

// maxStatusTargets bounds one status report.
const maxStatusTargets = 500

// Config returns the authenticated agent's remote targets. The response
// carries an ETag (the config version); a matching If-None-Match gets a
// 304, so the agent can poll often and cheaply.
func (h *Handler) Config(w http.ResponseWriter, r *http.Request) {
	agentID, _, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	cfg, err := h.Store.AgentConfig(r.Context(), agentID)
	if err != nil {
		log.Printf("agent %s: config: %v", agentID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	etag := `"` + cfg.Version + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

type statusRequest struct {
	// SSHPublicKey is the agent's own public key (authorized_keys format).
	SSHPublicKey string         `json:"ssh_public_key"`
	Targets      []targetStatus `json:"targets"`
}

type targetStatus struct {
	Ref string `json:"ref"`
	// ErrorCode is "" when the target was reached and collected.
	ErrorCode string `json:"error_code"`
	Error     string `json:"error"`
	// HostKey is the key the target presented, "" if the agent didn't
	// get as far as the SSH handshake.
	HostKey string `json:"host_key"`
}

// Status records the agent's SSH public key and per-target connection
// outcomes. Invalid keys and unknown error codes reject the whole report
// (400): they can only come from a broken or hostile agent.
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	agentID, _, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req statusRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if len(req.Targets) > maxStatusTargets {
		http.Error(w, "too many targets", http.StatusBadRequest)
		return
	}
	rep := store.StatusReport{}
	if req.SSHPublicKey != "" {
		k, err := sshkey.Normalize(req.SSHPublicKey)
		if err != nil {
			http.Error(w, "invalid ssh_public_key", http.StatusBadRequest)
			return
		}
		rep.SSHPublicKey = k
	}
	for _, t := range req.Targets {
		ref := strings.TrimSpace(t.Ref)
		if ref == "" || ref == store.LocalRef || len(ref) > 64 || !store.ValidTargetCode(t.ErrorCode) {
			http.Error(w, "invalid target status", http.StatusBadRequest)
			return
		}
		ts := store.TargetStatus{Ref: ref, ErrorCode: t.ErrorCode, Error: t.Error}
		if t.HostKey != "" {
			k, err := sshkey.Normalize(t.HostKey)
			if err != nil {
				http.Error(w, "invalid host_key", http.StatusBadRequest)
				return
			}
			ts.PresentedHostKey = k
		}
		rep.Targets = append(rep.Targets, ts)
	}
	if err := h.Store.RecordAgentStatus(r.Context(), agentID, rep); err != nil {
		log.Printf("agent %s: record status: %v", agentID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
