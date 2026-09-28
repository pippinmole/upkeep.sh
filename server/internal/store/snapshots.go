package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/hostfacts"
	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
)

type SnapshotInput struct {
	// AgentID is the authenticated agent. When set, the host is resolved
	// from Host inside the snapshot transaction (resolveHost) and HostID
	// must be empty. When empty (tests, tools), HostID names the host
	// directly and no agent bookkeeping happens.
	AgentID string
	Agent   AgentReport
	Host    HostClaim
	HostID  string

	SchemaVersion int
	CollectedAt   time.Time
	OSID          string
	OSVersionID   string
	OSCodename    string
	// OSFamily ("linux" | "windows" | "macos") and OSKnown drive the
	// hosts.os_* summary: OS fields are copied only when OSKnown (the os
	// collector succeeded); an empty OSFamily leaves hosts.os_family as is.
	OSFamily string
	OSKnown  bool
	// KernelRelease is the running kernel (payload os.kernel), "" when
	// unknown (older agent, or the kernel collector did not succeed).
	KernelRelease    string
	RebootRequired   bool
	RebootPackages   []string
	SourceIP         string
	PublicIPv4       string
	PublicIPv6       string
	ListeningSockets []SocketInput

	// CollectorStatus is the payload's collectors map as JSON, stored
	// verbatim in snapshots.collector_status. nil = not reported (older
	// agent), stored as NULL.
	CollectorStatus json.RawMessage

	// Inventory holds one authoritative Set per ecosystem (built by
	// ingest.planInventory). Ecosystems not present here are not diffed.
	Inventory []inventory.Set
	// FactSets holds one authoritative (or additive) set per host fact
	// kind: services, listeners, users (built by ingest.planFacts). Kinds
	// not present here are not diffed.
	FactSets []hostfacts.Set

	// Docker (migration 0013). Container and image ranges are FactSets
	// (kinds "containers:docker", "images:docker"); these are the rest,
	// each nil / empty when its collector wasn't ok.
	//   DockerImages: content of fully inspected images, interned into
	//     container_images before the ranges are applied.
	//   DockerEngine / DockerNetworks: the host_docker row.
	//   SwarmServices: a manager's services for its cluster.
	DockerImages   []ContainerImage
	DockerEngine   *DockerEngineInput
	DockerNetworks *DockerNetworksInput
	SwarmServices  *SwarmServicesInput

	// UptimeSeconds: nil when unknown (uptime collector not ok, older agent).
	UptimeSeconds *int64
	// Arch is the host's architecture (payload os.arch), "" when unknown.
	// hosts.arch keeps its previous value while unknown: the architecture
	// doesn't change, and one failed collection shouldn't erase it.
	Arch string
	// Facts is the validated snapshots.facts JSON (hostfacts.LinuxFacts);
	// nil stores '{}'.
	Facts []byte
	// InventoryAt is the range boundary for this push: collected_at,
	// clamped by the caller to no later than the server's clock.
	InventoryAt time.Time

	// AfterWrite, if set, runs inside the snapshot transaction after
	// everything is written and before commit. Ingest uses it to enqueue
	// matcher/findings jobs with River's InsertTx, so the jobs exist if
	// and only if the snapshot does. An error rolls the push back.
	AfterWrite func(ctx context.Context, tx pgx.Tx, res SnapshotResult) error
}

// SnapshotResult reports what InsertSnapshot did, for logging and tests.
type SnapshotResult struct {
	SnapshotID string
	// HostID is the host the snapshot was stored under; Host says how it
	// was resolved (zero when SnapshotInput.HostID was given).
	HostID    string
	Host      HostResolution
	Inventory []InventoryResult
	Facts     []FactResult
	// SwarmServices is set when the push carried a manager's services.
	SwarmServices *FactResult
	// KernelChanged: this snapshot is the host's newest (by collected_at)
	// and its kernel_release differs from the previous newest one's
	// (including unknown <-> known), i.e. the host rebooted into another
	// kernel or its agent started reporting it. Findings for kernel
	// packages depend on it (running-kernel policy).
	KernelChanged bool
}

// InventoryChanged reports whether any ecosystem's ranges opened or closed.
func (r SnapshotResult) InventoryChanged() bool {
	for _, inv := range r.Inventory {
		if inv.Added+inv.Removed > 0 {
			return true
		}
	}
	return false
}

// RematchSoftwareIDs are the versions this push needs evaluated: newly
// interned ones, plus existing ones whose inferred source was replaced by
// a real one (which reset their matcher bookkeeping).
func (r SnapshotResult) RematchSoftwareIDs() []int64 {
	var ids []int64
	for _, inv := range r.Inventory {
		ids = append(ids, inv.NewSoftwareIDs...)
		ids = append(ids, inv.ResetSoftwareIDs...)
	}
	return ids
}

type SocketInput struct {
	Proto, LocalAddr, ProcessName string
	Port, PID                     int
	IsPublic                      bool
}

// InsertSnapshot writes a full snapshot (row, sockets) and applies its
// package inventory to host_software, all in one transaction. It keeps
// every historical snapshot rather than upserting the latest, so drift and
// findings history stay auditable.
//
// The host row is locked first (FOR NO KEY UPDATE), so concurrent pushes
// for one host serialise: each sees the previous one's ranges and state.
// Pushes for different hosts don't contend except on shared
// software_versions rows, which are interned in a fixed order.
func (s *Store) InsertSnapshot(ctx context.Context, in SnapshotInput) (res SnapshotResult, err error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)

	if in.AgentID != "" {
		if in.HostID != "" {
			return res, errors.New("SnapshotInput: AgentID and HostID are mutually exclusive")
		}
		if res.Host, err = resolveHost(ctx, tx, in.AgentID, in.Host, in.Agent); err != nil {
			return res, err
		}
		in.HostID = res.Host.HostID
	}
	res.HostID = in.HostID

	var locked string
	if err := tx.QueryRow(ctx, `SELECT id FROM hosts WHERE id = $1 FOR NO KEY UPDATE`, in.HostID).Scan(&locked); err != nil {
		return res, fmt.Errorf("lock host: %w", err)
	}

	var hashes []byte // snapshots.package_set_hashes: {"deb": "<hex>"}, NULL if none
	if len(in.Inventory) > 0 {
		m := make(map[string]string, len(in.Inventory))
		for _, set := range in.Inventory {
			m[set.Ecosystem] = set.Hash
		}
		if hashes, err = json.Marshal(m); err != nil {
			return res, err
		}
	}
	var collectorStatus any
	if len(in.CollectorStatus) > 0 {
		collectorStatus = string(in.CollectorStatus)
	}

	// pgx encodes a nil []string as SQL NULL, not as an empty array, which
	// bypasses the column's `DEFAULT '{}'` (defaults only apply when a
	// column is omitted from the INSERT, not when NULL is passed
	// explicitly) and trips its NOT NULL constraint. The agent leaves this
	// nil whenever no reboot is pending, which is the common case.
	rebootPackages := in.RebootPackages
	if rebootPackages == nil {
		rebootPackages = []string{}
	}

	// The previous newest snapshot's kernel, to detect a reboot into another
	// kernel (read before inserting this one).
	var (
		prevKernel    *string
		prevCollected time.Time
		havePrev      = true
	)
	err = tx.QueryRow(ctx, `
		SELECT kernel_release, collected_at FROM snapshots WHERE host_id = $1
		ORDER BY collected_at DESC, received_at DESC LIMIT 1
	`, in.HostID).Scan(&prevKernel, &prevCollected)
	if errors.Is(err, pgx.ErrNoRows) {
		havePrev = false
	} else if err != nil {
		return res, err
	}
	newest := !havePrev || !in.CollectedAt.Before(prevCollected)
	if !havePrev {
		res.KernelChanged = in.KernelRelease != ""
	} else if newest {
		res.KernelChanged = in.KernelRelease != deref(prevKernel)
	}

	facts := "{}"
	if len(in.Facts) > 0 {
		facts = string(in.Facts)
	}

	var snapshotID string
	err = tx.QueryRow(ctx, `
		INSERT INTO snapshots (
			host_id, schema_version, collected_at, os_id, os_version_id,
			os_codename, reboot_required, reboot_packages, source_ip,
			public_ipv4, public_ipv6, collector_status, package_set_hashes, kernel_release, agent_id,
			uptime_seconds, arch, facts
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, '')::inet,
			NULLIF($10, '')::inet, NULLIF($11, '')::inet, $12::jsonb, $13::jsonb, NULLIF($14, ''), NULLIF($15, '')::uuid,
			$16, NULLIF($17, ''), $18::jsonb)
		RETURNING id
	`, in.HostID, in.SchemaVersion, in.CollectedAt, in.OSID, in.OSVersionID, in.OSCodename,
		in.RebootRequired, rebootPackages, in.SourceIP,
		in.PublicIPv4, in.PublicIPv6, collectorStatus, nullableJSON(hashes), in.KernelRelease, in.AgentID,
		in.UptimeSeconds, in.Arch, facts).Scan(&snapshotID)
	if err != nil {
		return res, err
	}
	res.SnapshotID = snapshotID

	// Host summary: last seen always; hostname and OS only from the newest
	// snapshot (an out-of-order older push must not roll them back). The
	// kernel mirrors the newest snapshot's value, NULL when unknown, the
	// same "running kernel" the findings policy uses.
	if _, err := tx.Exec(ctx, `
		UPDATE hosts SET
			last_seen_at = now(),
			hostname    = CASE WHEN $2 AND $3 <> '' THEN $3 ELSE hostname END,
			os_family   = CASE WHEN $2 AND $4 <> '' THEN $4 ELSE os_family END,
			os_id       = CASE WHEN $2 AND $5 THEN NULLIF($6, '') ELSE os_id END,
			os_version  = CASE WHEN $2 AND $5 THEN NULLIF($7, '') ELSE os_version END,
			os_codename = CASE WHEN $2 AND $5 THEN NULLIF($8, '') ELSE os_codename END,
			kernel      = CASE WHEN $2 THEN NULLIF($9, '') ELSE kernel END,
			arch        = CASE WHEN $2 AND $10 <> '' THEN $10 ELSE arch END
		WHERE id = $1
	`, in.HostID, newest, in.Host.Hostname, in.OSFamily, in.OSKnown,
		in.OSID, in.OSVersionID, in.OSCodename, in.KernelRelease, in.Arch); err != nil {
		return res, fmt.Errorf("update host summary: %w", err)
	}

	// listening_sockets is still written per snapshot (TCP and UDP) even
	// though host_listeners now holds the ranges: it is the only record of
	// the owning pid, and the planned exposure scanner's is_public lives
	// here (DOMAIN_MODEL.md §4.5 "As implemented"). Its primary key is
	// (snapshot, proto, addr, port), and SO_REUSEPORT lets several sockets
	// share one, so keep the first of each.
	type sockKey struct {
		proto, addr string
		port        int
	}
	seenSock := map[sockKey]bool{}
	sockRows := make([][]any, 0, len(in.ListeningSockets))
	for _, sock := range in.ListeningSockets {
		k := sockKey{sock.Proto, sock.LocalAddr, sock.Port}
		if seenSock[k] {
			continue
		}
		seenSock[k] = true
		sockRows = append(sockRows, []any{snapshotID, sock.Proto, sock.LocalAddr, sock.Port, nullableInt(sock.PID), sock.ProcessName, sock.IsPublic})
	}
	if len(sockRows) > 0 {
		if _, err := tx.CopyFrom(ctx,
			pgx.Identifier{"listening_sockets"},
			[]string{"snapshot_id", "proto", "local_addr", "port", "pid", "process_name", "is_public"},
			pgx.CopyFromRows(sockRows),
		); err != nil {
			return res, err
		}
	}

	for _, set := range in.Inventory {
		r, err := applyInventory(ctx, tx, in.HostID, snapshotID, in.InventoryAt, set)
		if err != nil {
			return res, fmt.Errorf("apply %s inventory: %w", set.Ecosystem, err)
		}
		res.Inventory = append(res.Inventory, r)
	}
	// Image content first: host_images references it.
	if err := internContainerImages(ctx, tx, in.DockerImages); err != nil {
		return res, err
	}
	for _, set := range in.FactSets {
		r, err := applyFactSet(ctx, tx, in.HostID, snapshotID, in.InventoryAt, set)
		if err != nil {
			return res, fmt.Errorf("apply %s: %w", set.Kind, err)
		}
		res.Facts = append(res.Facts, r)
	}
	if err := applyDockerHost(ctx, tx, in.HostID, snapshotID, in.InventoryAt, in.DockerEngine, in.DockerNetworks); err != nil {
		return res, err
	}
	if in.SwarmServices != nil {
		r, err := applySwarmServices(ctx, tx, in.HostID, snapshotID, in.InventoryAt, *in.SwarmServices)
		if err != nil {
			return res, fmt.Errorf("apply swarm services: %w", err)
		}
		res.SwarmServices = &r
	}

	if in.AfterWrite != nil {
		if err := in.AfterWrite(ctx, tx, res); err != nil {
			return res, fmt.Errorf("after write: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return res, err
	}
	return res, nil
}

func nullableJSON(b []byte) any {
	if b == nil {
		return nil
	}
	return string(b)
}

func nullableInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}
