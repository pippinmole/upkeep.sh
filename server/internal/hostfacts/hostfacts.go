// Package hostfacts holds the pure (DB-free) logic for the per-concept
// host range tables other than packages: services, listeners and local
// users (DOMAIN_MODEL.md §4.5, option D). It mirrors package inventory:
// canonical sets, a set hash that short-circuits unchanged pushes, and a
// diff against the open ranges. The storage side is store.applyFactSet;
// the payload → Set mapping, including which collectors are
// authoritative, lives in ingest.
//
// Unlike packages, these rows have a natural key (a service name, a
// socket address, a user name) plus attributes that can change in place
// (a service's state, a listener's process). A row's identity for range
// purposes is its full value: any attribute change closes the key's open
// range and opens a new one, so history shows when a service stopped or a
// port changed owner. At most one range per (host, key) is open.
package hostfacts

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
)

// Table describes one range table: its name, the value columns every row
// supplies (in order), and the optional scope column that partitions a
// host's rows between independent collectors (host_listeners.transport:
// the TCP and UDP collectors succeed or fail on their own).
//
// Every range table also has host_id, row_key, row_hash, first_seen_at,
// first_seen_snapshot_id, removed_at and removed_snapshot_id.
type Table struct {
	Name     string
	ScopeCol string // "" = no scope; the kind covers all of a host's rows
	Columns  []string
	// Detail columns (optional; the table then has a detail_hash column)
	// are the ones a partial row doesn't know: Docker objects whose
	// inspect failed. They are part of the row's identity through
	// Row.DetailHash, and a partial row takes them over from the key's
	// open range instead of overwriting them with NULLs.
	Detail []string
	// Live columns (optional; the table then has a live_hash column) are
	// stored on the range but never hashed into row_hash: a change updates
	// the open range in place instead of opening a new one (a container's
	// started_at, a service's running task count).
	Live []string
}

var (
	ServicesTable = Table{Name: "host_services", ScopeCol: "manager",
		Columns: []string{"manager", "name", "display_name", "start_mode", "state", "run_as", "binary_path", "attrs"}}
	ListenersTable = Table{Name: "host_listeners", ScopeCol: "transport",
		Columns: []string{"transport", "proto", "local_addr", "port", "process_name"}}
	UsersTable = Table{Name: "host_users",
		Columns: []string{"name", "uid", "gid", "home", "shell", "groups", "login_shell", "admin"}}

	// Docker (migration 0013). Containers and images belong to a host;
	// SwarmServicesTable's rows belong to a (user, cluster) instead of a
	// host (store.applySwarmServices).
	ContainersTable = Table{Name: "host_containers",
		Columns: []string{"container_id", "name", "image", "image_id", "state",
			"compose_project", "compose_service", "swarm_stack", "swarm_service_id", "swarm_service_name", "swarm_task_id", "labels"},
		Detail: []string{"ports", "networks", "network_mode", "privileged", "restart_policy", "mounts"},
		Live:   []string{"started_at", "inspect_error"}}
	HostImagesTable = Table{Name: "host_images",
		Columns: []string{"image_id", "repo_tags", "repo_digests"},
		Detail:  []string{"os", "arch", "variant"},
		Live:    []string{"inspect_error"}}
	SwarmServicesTable = Table{Name: "swarm_services",
		Columns: []string{"service_id", "name", "image", "mode", "replicas", "swarm_stack", "labels", "ports"},
		Live:    []string{"running_tasks", "desired_tasks"}}
)

// Row is one reported item. Key is its natural key within the table
// (unique per host among open ranges); Values line up with the table's
// Columns. Hash is computed by NewSet.
type Row struct {
	Key    string
	Values []any
	// Detail lines up with Table.Detail; ignored when Partial.
	Detail []any
	// Live lines up with Table.Live. On a Partial row a nil value means
	// unknown: the stored value is kept.
	Live []any
	// Partial: the item exists but its detail is unknown (inspect failed).
	Partial bool

	Hash string
	// DetailHash is the hash of Detail (tables with Detail columns). A
	// partial row has "" (unknown) until the store gives it the open
	// range's (WithDetailHash).
	DetailHash string
	LiveHash   string // hash of Live (tables with Live columns)
}

// Set is the authoritative (or, when Additive, partial) state of one kind
// on one host at one point in time: only built from a collector whose
// status was ok.
type Set struct {
	// Kind keys host_fact_state: "services:systemd", "listeners:tcp",
	// "listeners:udp", "users:local".
	Kind  string
	Table Table
	Scope string // value of Table.ScopeCol for every row; "" when unscoped
	Rows  []Row  // sorted by Key, unique on Key
	// Additive is set when the collector truncated its list: rows are
	// opened and changed rows replaced, but nothing absent is closed.
	Additive bool
	Hash     string
}

// hashVersion is mixed into every row and set hash. Bump it when the
// canonical encoding changes: every stored hash then mismatches once,
// which costs one idempotent full diff per host and kind. Changing the
// row hash also closes and reopens every open range once, so prefer not
// to.
const hashVersion = "upkeep-hostfacts-v1"

// NewSet canonicalises rows (sorted by Key, duplicates dropped keeping the
// first) and computes row and set hashes.
func NewSet(kind string, table Table, scope string, rows []Row, additive bool) Set {
	sorted := slices.Clone(rows)
	slices.SortStableFunc(sorted, func(a, b Row) int { return cmp.Compare(a.Key, b.Key) })
	sorted = slices.CompactFunc(sorted, func(a, b Row) bool { return a.Key == b.Key })
	if sorted == nil {
		sorted = []Row{}
	}
	set := Set{Kind: kind, Table: table, Scope: scope, Rows: sorted, Additive: additive}
	h := sha256.New()
	writeFields(h, hashVersion, kind, table.Name, scope)
	for i := range sorted {
		r := &sorted[i]
		if len(table.Detail) > 0 {
			r.DetailHash = ""
			if !r.Partial {
				r.DetailHash = valuesHash(table.Name+"/detail", r.Key, r.Detail)
			}
		}
		if len(table.Live) > 0 {
			r.LiveHash = valuesHash(table.Name+"/live", r.Key, r.Live)
		}
		r.Hash = rowHash(table, *r)
		if len(table.Detail) > 0 || len(table.Live) > 0 {
			// Live values and partialness are part of what the set
			// reports, so a change to either must not short-circuit.
			writeFields(h, r.Key, r.Hash, r.LiveHash, strconv.FormatBool(r.Partial))
		} else {
			writeFields(h, r.Key, r.Hash)
		}
	}
	set.Hash = hex.EncodeToString(h.Sum(nil))
	return set
}

// rowHash is SHA-256 over the key and the JSON encoding of every value.
// JSON gives each Go value one stable text form (maps are encoded with
// sorted keys), and distinguishes nil from "" and 0.
//
// For tables with Detail columns the detail enters through DetailHash, so
// a partial row given its predecessor's detail hash hashes exactly like
// the full row it stands in for.
func rowHash(t Table, r Row) string {
	h := sha256.New()
	writeFields(h, hashVersion, t.Name, r.Key)
	writeValues(h, r.Values)
	if len(t.Detail) > 0 {
		writeFields(h, "detail", r.DetailHash)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func valuesHash(domain, key string, values []any) string {
	h := sha256.New()
	writeFields(h, hashVersion, domain, key)
	writeValues(h, values)
	return hex.EncodeToString(h.Sum(nil))
}

func writeValues(h writer, values []any) {
	for _, v := range values {
		b, err := json.Marshal(v)
		if err != nil {
			b = []byte("!unencodable")
		}
		writeFields(h, string(b))
	}
}

// WithDetailHash returns r (a partial row) standing in for its open
// range: the given detail hash (the range's detail_hash) and the row hash
// recomputed with it. The set hash is unaffected: it describes what was
// reported.
func WithDetailHash(t Table, r Row, detailHash string) Row {
	r.DetailHash = detailHash
	r.Hash = rowHash(t, r)
	return r
}

type writer interface{ Write([]byte) (int, error) }

func writeFields(w writer, fields ...string) {
	var b strings.Builder
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(0)
		}
		b.WriteString(f)
	}
	b.WriteByte('\n')
	_, _ = w.Write([]byte(b.String()))
}

// Open is what the store knows about one open range.
type Open struct {
	Hash       string
	DetailHash string // tables with Detail columns
	LiveHash   string // tables with Live columns
}

// DiffRanges is Diff for tables with Detail / Live columns. live are rows
// whose range stays open but whose live values changed (update in place).
// Partial rows must already carry their open range's detail hash
// (WithDetailHash).
func DiffRanges(open map[string]Open, set Set) (add []Row, closeKeys []string, live []Row) {
	reported := make(map[string]bool, len(set.Rows))
	for _, r := range set.Rows {
		reported[r.Key] = true
		cur, ok := open[r.Key]
		switch {
		case !ok:
			add = append(add, r)
		case cur.Hash != r.Hash:
			add = append(add, r)
			closeKeys = append(closeKeys, r.Key)
		case len(set.Table.Live) > 0 && cur.LiveHash != r.LiveHash:
			live = append(live, r)
		}
	}
	if !set.Additive {
		for k := range open {
			if !reported[k] {
				closeKeys = append(closeKeys, k)
			}
		}
	}
	slices.Sort(closeKeys)
	return add, closeKeys, live
}

// Diff compares a host's open ranges for one kind (row_key -> row_hash)
// with a reported set. add are rows to open; closeKeys are keys whose open
// range must be closed (sorted). A key reported with a different hash is
// in both: its old range closes and a new one opens. Keys missing from the
// report are closed only when the set is not Additive.
func Diff(open map[string]string, set Set) (add []Row, closeKeys []string) {
	reported := make(map[string]bool, len(set.Rows))
	for _, r := range set.Rows {
		reported[r.Key] = true
		cur, ok := open[r.Key]
		switch {
		case !ok:
			add = append(add, r)
		case cur != r.Hash:
			add = append(add, r)
			closeKeys = append(closeKeys, r.Key)
		}
	}
	if !set.Additive {
		for k := range open {
			if !reported[k] {
				closeKeys = append(closeKeys, k)
			}
		}
	}
	slices.Sort(closeKeys)
	return add, closeKeys
}
