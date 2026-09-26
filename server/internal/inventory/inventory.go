// Package inventory holds the pure (DB-free) logic for package inventory
// history: canonical package sets, their hash, and the range diff. The
// storage side lives in store (ApplyInventory); the payload → Set mapping,
// including the rules for old agents and failed collectors, lives in
// ingest. See docs/DOMAIN_MODEL.md §2.2.
package inventory

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
)

// Item is one installed package version as reported, after defaulting.
// (Name, Version, Arch) is its identity within a Set; Source/SourceVersion
// are attributes of that identity (see software_versions in migration
// 0003 for why source is not part of the interned key).
type Item struct {
	Name, Version, Arch   string
	Source, SourceVersion string
	// SourceInferred is true when the agent did not send a source (older
	// agents) and Source/SourceVersion were defaulted to the binary's.
	SourceInferred bool
}

// Set is the authoritative inventory of one ecosystem on one host at one
// point in time: only built from a collector whose status was ok.
//
// Distro/Release scope the interned versions (software_versions key): the
// same "deb" name/version on jammy and on bookworm are different rows,
// because advisories are per release. Ecosystems that are not
// distro-scoped leave both empty.
type Set struct {
	Ecosystem string
	Distro    string
	Release   string
	Items     []Item // sorted by (Name, Version, Arch), unique on that key
	Hash      string
}

// hashVersion is mixed into every set hash. Bump it whenever the canonical
// encoding below changes: every host's stored hash then mismatches once,
// which costs one full (idempotent) diff per host and nothing else.
const hashVersion = "upkeep-pkgset-v1"

// NewSet canonicalises items (sorts, drops exact-key duplicates keeping the
// first after sorting) and computes the set hash.
func NewSet(ecosystem, distro, release string, items []Item) Set {
	sorted := slices.Clone(items)
	slices.SortFunc(sorted, compareItems)
	sorted = slices.CompactFunc(sorted, func(a, b Item) bool { return itemKey(a) == itemKey(b) })
	if sorted == nil {
		sorted = []Item{}
	}
	s := Set{Ecosystem: ecosystem, Distro: distro, Release: release, Items: sorted}
	s.Hash = hashSet(s)
	return s
}

type key struct{ name, version, arch string }

func itemKey(it Item) key { return key{it.Name, it.Version, it.Arch} }

// compareItems orders by identity first, then by attributes, so that the
// duplicate kept by CompactFunc is deterministic regardless of input order.
func compareItems(a, b Item) int {
	if c := cmp.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Version, b.Version); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Arch, b.Arch); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Source, b.Source); c != 0 {
		return c
	}
	if c := cmp.Compare(a.SourceVersion, b.SourceVersion); c != 0 {
		return c
	}
	// non-inferred (real) source sorts first, so it wins a duplicate.
	switch {
	case a.SourceInferred == b.SourceInferred:
		return 0
	case !a.SourceInferred:
		return -1
	default:
		return 1
	}
}

// hashSet is SHA-256 over a NUL-separated canonical encoding of the scope
// and every item (including the source fields and the inferred flag, so an
// agent upgrade that starts sending real source names changes the hash and
// triggers one intern pass that corrects the interned source). Callers
// guarantee fields contain no NUL bytes (ingest drops such items).
func hashSet(s Set) string {
	h := sha256.New()
	var b strings.Builder
	write := func(fields ...string) {
		b.Reset()
		for i, f := range fields {
			if i > 0 {
				b.WriteByte(0)
			}
			b.WriteString(f)
		}
		b.WriteByte('\n')
		h.Write([]byte(b.String()))
	}
	write(hashVersion, s.Ecosystem, s.Distro, s.Release)
	for _, it := range s.Items {
		inferred := "0"
		if it.SourceInferred {
			inferred = "1"
		}
		write(it.Name, it.Version, it.Arch, it.Source, it.SourceVersion, inferred)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Diff compares the software ids a host currently has open ranges for
// (within one ecosystem) against the ids just reported for it. added gets
// a new open range; removed gets its open range closed. Both results are
// sorted and unique; duplicate ids in either input are tolerated.
func Diff(open, reported []int64) (added, removed []int64) {
	openSet := make(map[int64]struct{}, len(open))
	for _, id := range open {
		openSet[id] = struct{}{}
	}
	repSet := make(map[int64]struct{}, len(reported))
	for _, id := range reported {
		repSet[id] = struct{}{}
	}
	for id := range repSet {
		if _, ok := openSet[id]; !ok {
			added = append(added, id)
		}
	}
	for id := range openSet {
		if _, ok := repSet[id]; !ok {
			removed = append(removed, id)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}
