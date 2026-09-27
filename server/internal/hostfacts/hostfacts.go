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
}

var (
	ServicesTable = Table{Name: "host_services", ScopeCol: "manager",
		Columns: []string{"manager", "name", "display_name", "start_mode", "state", "run_as", "binary_path", "attrs"}}
	ListenersTable = Table{Name: "host_listeners", ScopeCol: "transport",
		Columns: []string{"transport", "proto", "local_addr", "port", "process_name"}}
	UsersTable = Table{Name: "host_users",
		Columns: []string{"name", "uid", "gid", "home", "shell", "groups", "login_shell", "admin"}}
)

// Row is one reported item. Key is its natural key within the table
// (unique per host among open ranges); Values line up with the table's
// Columns. Hash is computed by NewSet.
type Row struct {
	Key    string
	Values []any
	Hash   string
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
		sorted[i].Hash = rowHash(table, sorted[i])
		writeFields(h, sorted[i].Key, sorted[i].Hash)
	}
	set.Hash = hex.EncodeToString(h.Sum(nil))
	return set
}

// rowHash is SHA-256 over the key and the JSON encoding of every value.
// JSON gives each Go value one stable text form (maps are encoded with
// sorted keys), and distinguishes nil from "" and 0.
func rowHash(t Table, r Row) string {
	h := sha256.New()
	writeFields(h, hashVersion, t.Name, r.Key)
	for _, v := range r.Values {
		b, err := json.Marshal(v)
		if err != nil {
			b = []byte("!unencodable")
		}
		writeFields(h, string(b))
	}
	return hex.EncodeToString(h.Sum(nil))
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
