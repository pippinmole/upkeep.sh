package store

// Remote targets (DOMAIN_MODEL.md §4.2, migration 0012): the ssh
// assignments an agent collects besides its own machine, and the status it
// reports back for them.
//
// The server never connects to an agent. The agent pulls its target list
// (AgentConfig, GET /v1/agent/config) and reports what happened when it
// tried to reach each target (RecordAgentStatus, POST /v1/agent/status).
// Successful collections arrive as ordinary snapshot pushes whose host.ref
// is the target ref (resolveRemoteHost).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// RemoteTarget is one remote assignment as the agent sees it.
type RemoteTarget struct {
	Ref      string `json:"ref"`
	Mode     string `json:"mode"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	// HostKey is the host key the user confirmed ("type base64"), "" if
	// none yet: the agent then only fetches the key the host presents
	// and reports it, without authenticating.
	HostKey string `json:"host_key"`
}

// AgentConfig is the agent's desired state.
type AgentConfig struct {
	// Version changes whenever anything in Targets does (ETag).
	Version string         `json:"version"`
	Targets []RemoteTarget `json:"targets"`
}

// AgentConfig returns the enabled remote assignments of an agent.
func (s *Store) AgentConfig(ctx context.Context, agentID string) (AgentConfig, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT ah.target_ref, ah.mode, ah.address, ah.port, ah.username, COALESCE(ah.host_key, '')
		FROM agent_hosts ah JOIN hosts h ON h.id = ah.host_id
		WHERE ah.agent_id = $1 AND ah.mode <> 'local' AND ah.enabled
		ORDER BY ah.target_ref
	`, agentID)
	if err != nil {
		return AgentConfig{}, err
	}
	defer rows.Close()
	cfg := AgentConfig{Targets: []RemoteTarget{}}
	for rows.Next() {
		var t RemoteTarget
		if err := rows.Scan(&t.Ref, &t.Mode, &t.Address, &t.Port, &t.Username, &t.HostKey); err != nil {
			return AgentConfig{}, err
		}
		cfg.Targets = append(cfg.Targets, t)
	}
	if err := rows.Err(); err != nil {
		return AgentConfig{}, err
	}
	b, err := json.Marshal(cfg.Targets)
	if err != nil {
		return AgentConfig{}, err
	}
	sum := sha256.Sum256(b)
	cfg.Version = hex.EncodeToString(sum[:12])
	return cfg, nil
}

// Target status codes an agent may report (agent_hosts.last_error_code).
const (
	TargetHostKeyUnconfirmed = "host_key_unconfirmed"
	TargetHostKeyMismatch    = "host_key_mismatch"
	TargetAuthFailed         = "auth_failed"
	TargetUnreachable        = "unreachable"
	TargetSFTPFailed         = "sftp_failed"
	TargetPushFailed         = "push_failed"
)

var targetCodes = map[string]bool{
	TargetHostKeyUnconfirmed: true, TargetHostKeyMismatch: true, TargetAuthFailed: true,
	TargetUnreachable: true, TargetSFTPFailed: true, TargetPushFailed: true,
}

// ValidTargetCode reports whether code is "" (healthy) or a known code.
func ValidTargetCode(code string) bool { return code == "" || targetCodes[code] }

// TargetStatus is one target's outcome in a status report. Keys are
// already normalized ("type base64") by the caller.
type TargetStatus struct {
	Ref       string
	ErrorCode string // "" = connected and collected
	Error     string // human-readable detail
	// PresentedHostKey is the key the host presented, "" if the agent
	// didn't get that far.
	PresentedHostKey string
}

// StatusReport is a POST /v1/agent/status body, validated.
type StatusReport struct {
	SSHPublicKey string // "" leaves the stored key unchanged
	Targets      []TargetStatus
}

// RecordAgentStatus stores an agent's public key and its per-target
// outcomes. Refs the agent has no remote assignment for are ignored (the
// assignment was removed after the agent fetched its config).
//
// Host keys: a presented key that differs from the confirmed one (or with
// none confirmed) becomes host_key_pending for the user to confirm; one
// equal to the confirmed key clears it. A host-key error for a key that
// is now confirmed came from a config the agent fetched before the user
// confirmed it, so it only records the attempt.
func (s *Store) RecordAgentStatus(ctx context.Context, agentID string, rep StatusReport) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if rep.SSHPublicKey != "" {
		if _, err := tx.Exec(ctx, `UPDATE agents SET ssh_public_key = $2 WHERE id = $1`, agentID, rep.SSHPublicKey); err != nil {
			return fmt.Errorf("store ssh key: %w", err)
		}
	}
	for _, t := range rep.Targets {
		if _, err := tx.Exec(ctx, `
			UPDATE agent_hosts SET
				last_attempt_at = now(),
				host_key_pending = CASE
					WHEN $3 = '' THEN host_key_pending
					WHEN $3 = host_key THEN NULL
					ELSE $3 END,
				last_error_code = CASE
					WHEN $4 IN ('host_key_unconfirmed', 'host_key_mismatch') AND $3 = host_key THEN last_error_code
					ELSE NULLIF($4, '') END,
				last_error = CASE
					WHEN $4 IN ('host_key_unconfirmed', 'host_key_mismatch') AND $3 = host_key THEN last_error
					ELSE NULLIF($5, '') END
			WHERE agent_id = $1 AND target_ref = $2 AND mode <> 'local'
		`, agentID, t.Ref, t.PresentedHostKey, t.ErrorCode, clipString(t.Error, 1000)); err != nil {
			return fmt.Errorf("record target %s: %w", t.Ref, err)
		}
	}
	return tx.Commit(ctx)
}

func clipString(s string, n int) string {
	if len(s) > n {
		s = s[:n] // may split a rune; dropped below
	}
	return strings.ToValidUTF8(s, "")
}
