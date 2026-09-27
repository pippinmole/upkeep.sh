package store

// Agents, and resolving which host a push describes (DOMAIN_MODEL.md §4.3).
//
// An agent is one deployed collector with its own credential. A host is one
// monitored machine. agent_hosts says which agent collects which host, in
// which mode; only 'local' (the machine the agent runs on) is implemented.
//
// Host resolution rules for a push from agent A with host.ref "local" and
// identity M (the host's machine-id, possibly unknown):
//
//  1. A already has a local host H (from an earlier push, or backfilled by
//     migration 0008): the push goes to H. Assignments are sticky. If M is
//     unclaimed within A's user it is recorded as an identity of H; if M
//     already belongs to another host, H is flagged duplicate_of that host
//     (once) and stays separate.
//  2. A has no local host (first push after enrollment):
//     - M unknown: a new host is created and assigned. Rule 1 makes every
//       later push of A land on it, so hosts are never duplicated per push.
//     - M unclaimed: a new host is created with identity M.
//     - M belongs to host I, and no OTHER active agent has I as its local
//       host: A re-attaches to I, keeping its history (agent reinstall),
//       and I is unarchived if it was archived.
//     - M belongs to host I that another active agent collects locally
//       (cloned VM, or a second agent on the same machine): a new host is
//       created, flagged duplicate_of I. Never merged automatically (Q12);
//       the dashboard merges or dismisses the flag (mgmt_merge_host /
//       mgmt_dismiss_duplicate, migration 0011), and a dismissed flag is
//       not raised again against the same host.
//
// "Active" (activeAgentSQL): not revoked, and seen within
// ActiveIntervals push intervals (the agent's reported interval, else
// DefaultPushInterval), but never less than MinActiveWindow.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// IdentityMachineID is host_identities.kind for Linux /etc/machine-id; kinds
// are the payload's host.identity keys.
const IdentityMachineID = "machine_id"

// LocalRef is the host.ref of an agent's own machine.
const LocalRef = "local"

const (
	// DefaultPushInterval is assumed for agents that don't report theirs.
	DefaultPushInterval = 15 * time.Minute
	// ActiveIntervals: an agent silent for more push intervals than this is
	// no longer active, so another agent may take over its host.
	ActiveIntervals = 3
	// MinActiveWindow floors the window for agents with very short
	// intervals (dev agents push every 30s).
	MinActiveWindow = 2 * time.Minute
)

// activeAgentSQL is true for an active agent row aliased "a".
var activeAgentSQL = fmt.Sprintf(`(a.revoked_at IS NULL AND a.last_seen_at IS NOT NULL
	AND a.last_seen_at >= now() - make_interval(secs => GREATEST(%d * COALESCE(a.push_interval_seconds, %d), %d)))`,
	ActiveIntervals, int(DefaultPushInterval.Seconds()), int(MinActiveWindow.Seconds()))

// ErrUnknownHostRef: the push names a remote target the agent has no
// assignment for.
var ErrUnknownHostRef = errors.New("unknown host ref")

// ErrAgentNotFound: the agent row is gone (deleted between auth and push).
var ErrAgentNotFound = errors.New("agent not found")

// EnrollInput is what enrollment knows about the new agent.
type EnrollInput struct {
	Token      string
	Hostname   string // the enrolling process's hostname, the default name
	Version    string
	Platform   string
	SecretHash string
}

// EnrollAgent consumes a one-time enrollment token and creates the agent
// with its credential, in one transaction. No host is created: that
// happens on the agent's first push. Returns pgx.ErrNoRows if the token is
// missing, expired or already used.
func (s *Store) EnrollAgent(ctx context.Context, in EnrollInput) (agentID string, err error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var userID string
	var tokenName *string
	if err := tx.QueryRow(ctx, `
		DELETE FROM enrollment_tokens
		WHERE token = $1 AND expires_at > now()
		RETURNING user_id, agent_name
	`, in.Token).Scan(&userID, &tokenName); err != nil {
		return "", err
	}
	name := in.Hostname
	if tokenName != nil && *tokenName != "" {
		name = *tokenName
	}
	if name == "" {
		name = "unknown-host"
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO agents (user_id, name, agent_version, platform)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''))
		RETURNING id
	`, userID, name, in.Version, in.Platform).Scan(&agentID); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_credentials (agent_id, secret_hash) VALUES ($1, $2)`,
		agentID, in.SecretHash); err != nil {
		return "", err
	}
	return agentID, tx.Commit(ctx)
}

// AgentReport is the payload's agent block. Empty fields leave the stored
// values unchanged.
type AgentReport struct {
	Version         string
	Platform        string
	IntervalSeconds int
}

// HostClaim is the payload's host block: which host the push describes.
type HostClaim struct {
	Ref       string // "" (older agents) = LocalRef
	MachineID string // "" = unknown
	Hostname  string // "" = unknown
}

// HostResolution reports how a push was mapped to a host.
type HostResolution struct {
	HostID string
	// Created: a new host was created for this push.
	Created bool
	// Reattached: the agent's first push attached it to an existing host by
	// identity (agent reinstall).
	Reattached bool
	// DuplicateOf is the host this one was (newly) flagged as a possible
	// duplicate of, "" if not flagged by this push.
	DuplicateOf string
}

// resolveHost maps a push from agentID onto a host, creating the host
// and/or the assignment as needed (rules in the file comment), and records
// the agent as seen. Runs inside the snapshot transaction; the agent row
// is locked first, so one agent's pushes resolve one at a time.
func resolveHost(ctx context.Context, tx pgx.Tx, agentID string, claim HostClaim, rep AgentReport) (res HostResolution, err error) {
	var userID, agentName string
	err = tx.QueryRow(ctx, `SELECT user_id, name FROM agents WHERE id = $1 FOR UPDATE`, agentID).Scan(&userID, &agentName)
	if errors.Is(err, pgx.ErrNoRows) {
		return res, ErrAgentNotFound
	} else if err != nil {
		return res, fmt.Errorf("lock agent: %w", err)
	}

	ref := claim.Ref
	if ref == "" {
		ref = LocalRef
	}
	if ref == LocalRef {
		res, err = resolveLocalHost(ctx, tx, userID, agentID, agentName, claim)
	} else {
		res, err = resolveRemoteHost(ctx, tx, userID, agentID, ref, claim)
	}
	if err != nil {
		return res, err
	}

	var interval any
	if rep.IntervalSeconds > 0 {
		interval = rep.IntervalSeconds
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agents SET last_seen_at = now(),
			agent_version = COALESCE(NULLIF($2, ''), agent_version),
			platform = COALESCE(NULLIF($3, ''), platform),
			push_interval_seconds = COALESCE($4::int, push_interval_seconds)
		WHERE id = $1
	`, agentID, rep.Version, rep.Platform, interval); err != nil {
		return res, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agent_hosts SET last_collected_at = now(), last_error = NULL
		WHERE agent_id = $1 AND host_id = $2
	`, agentID, res.HostID); err != nil {
		return res, err
	}
	return res, nil
}

func resolveLocalHost(ctx context.Context, tx pgx.Tx, userID, agentID, agentName string, claim HostClaim) (res HostResolution, err error) {
	// The identity is serialised per (user, kind, value) so two agents
	// claiming the same machine-id at once resolve one after the other.
	if claim.MachineID != "" {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			"host_identity:"+userID+":"+IdentityMachineID+":"+claim.MachineID); err != nil {
			return res, err
		}
	}

	var current string // the agent's existing local host
	err = tx.QueryRow(ctx, `SELECT host_id FROM agent_hosts WHERE agent_id = $1 AND mode = 'local'`, agentID).Scan(&current)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return res, err
	}

	owner, err := identityOwner(ctx, tx, userID, IdentityMachineID, claim.MachineID)
	if err != nil {
		return res, err
	}

	// Rule 1: sticky assignment.
	if current != "" {
		res.HostID = current
		switch {
		case claim.MachineID == "" || owner == current:
		case owner == "":
			if err := addIdentity(ctx, tx, userID, IdentityMachineID, claim.MachineID, current); err != nil {
				return res, err
			}
		default:
			flagged, err := flagDuplicate(ctx, tx, current, owner)
			if err != nil {
				return res, err
			}
			if flagged {
				res.DuplicateOf = owner
			}
		}
		return res, nil
	}

	// Rule 2: first push of this agent.
	if owner != "" {
		var taken bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM agent_hosts ah JOIN agents a ON a.id = ah.agent_id
				WHERE ah.host_id = $1 AND ah.mode = 'local' AND ah.agent_id <> $2 AND `+activeAgentSQL+`
			)`, owner, agentID).Scan(&taken); err != nil {
			return res, err
		}
		if !taken {
			if err := assignLocal(ctx, tx, agentID, owner); err != nil {
				return res, err
			}
			// A new agent installed on an archived host's machine brings it
			// back: someone deliberately monitors it again. (Merged hosts
			// own no identities, so they are never re-attached.)
			if _, err := tx.Exec(ctx, `UPDATE hosts SET archived_at = NULL WHERE id = $1 AND merged_into IS NULL`, owner); err != nil {
				return res, err
			}
			res.HostID, res.Reattached = owner, true
			return res, nil
		}
	}

	hostname := claim.Hostname
	if hostname == "" {
		hostname = agentName
	}
	if hostname == "" {
		hostname = "unknown-host"
	}
	var dup any
	if owner != "" {
		dup = owner
	}
	if err := tx.QueryRow(ctx, `INSERT INTO hosts (user_id, hostname, duplicate_of) VALUES ($1, $2, $3) RETURNING id`,
		userID, hostname, dup).Scan(&res.HostID); err != nil {
		return res, err
	}
	res.Created = true
	res.DuplicateOf = owner
	if owner == "" && claim.MachineID != "" {
		if err := addIdentity(ctx, tx, userID, IdentityMachineID, claim.MachineID, res.HostID); err != nil {
			return res, err
		}
	}
	return res, assignLocal(ctx, tx, agentID, res.HostID)
}

// resolveRemoteHost maps a remote target ref to its pre-created
// assignment. Remote collection is not implemented, so no such assignment
// exists yet; the path is here so a push can never create one implicitly.
func resolveRemoteHost(ctx context.Context, tx pgx.Tx, userID, agentID, ref string, claim HostClaim) (res HostResolution, err error) {
	err = tx.QueryRow(ctx, `
		SELECT host_id FROM agent_hosts WHERE agent_id = $1 AND target_ref = $2 AND enabled
	`, agentID, ref).Scan(&res.HostID)
	if errors.Is(err, pgx.ErrNoRows) {
		return res, ErrUnknownHostRef
	} else if err != nil {
		return res, err
	}
	if claim.MachineID == "" {
		return res, nil
	}
	owner, err := identityOwner(ctx, tx, userID, IdentityMachineID, claim.MachineID)
	if err != nil {
		return res, err
	}
	switch {
	case owner == res.HostID:
	case owner == "":
		err = addIdentity(ctx, tx, userID, IdentityMachineID, claim.MachineID, res.HostID)
	default:
		var flagged bool
		if flagged, err = flagDuplicate(ctx, tx, res.HostID, owner); flagged {
			res.DuplicateOf = owner
		}
	}
	return res, err
}

func identityOwner(ctx context.Context, tx pgx.Tx, userID, kind, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	var hostID string
	err := tx.QueryRow(ctx, `SELECT host_id FROM host_identities WHERE user_id = $1 AND kind = $2 AND value = $3`,
		userID, kind, value).Scan(&hostID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return hostID, err
}

func addIdentity(ctx context.Context, tx pgx.Tx, userID, kind, value, hostID string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO host_identities (user_id, kind, value, host_id) VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING
	`, userID, kind, value, hostID)
	return err
}

// flagDuplicate marks hostID as a possible duplicate of other, unless it is
// already flagged, or the user dismissed that flag ("not a duplicate",
// hosts.duplicate_dismissed_of). Reports whether it changed anything.
func flagDuplicate(ctx context.Context, tx pgx.Tx, hostID, other string) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE hosts SET duplicate_of = $2
		WHERE id = $1 AND duplicate_of IS NULL AND duplicate_dismissed_of IS DISTINCT FROM $2
	`, hostID, other)
	return tag.RowsAffected() > 0, err
}

func assignLocal(ctx context.Context, tx pgx.Tx, agentID, hostID string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO agent_hosts (agent_id, host_id, mode, target_ref) VALUES ($1, $2, 'local', 'local')
	`, agentID, hostID)
	return err
}
