// Package pkgsource collects installed packages from a target, one Source
// per package ecosystem, selected by the target's detected OS.
//
// Adding an ecosystem means writing one Source and adding it to Default().
// Planned sources, none implemented yet (DOMAIN_MODEL.md §4.8):
//
//   - rpm: RHEL/Fedora/SUSE, from var/lib/rpm/rpmdb.sqlite; Applies to
//     OS.Like("rhel", "fedora", "suse").
//   - apk: Alpine, from lib/apk/db/installed; Applies to OS.Like("alpine").
//   - windows programs: registry Uninstall keys, via a registry capability
//     on the target (see package target); Applies to FamilyWindows.
//   - macOS apps / pkg receipts / Homebrew: Info.plist, var/db/receipts,
//     Cellar directory listing; Applies to FamilyMacOS.
//
// A host can have several applicable sources (e.g. macOS apps + Homebrew),
// and each reports its own status, so one failing never hides another.
package pkgsource

import (
	"context"
	"fmt"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
	"github.com/pippinmole/upkeep.sh/agent/internal/detect"
	"github.com/pippinmole/upkeep.sh/agent/internal/target"
)

// Source reads one package ecosystem's installed-package database.
type Source interface {
	// Name is this source's key in Snapshot.Collectors, e.g. "deb_packages".
	// Must be unique within a Registry.
	Name() string
	// Ecosystem tags every package this source returns (e.g. "deb"). The
	// server keys interned versions on it (software_versions.ecosystem) and
	// diffs inventory per ecosystem, so a failing source only leaves its own
	// ecosystem's ranges untouched.
	Ecosystem() string
	// Applies reports whether this source is relevant to the detected OS.
	// It must decide from detection alone, not by probing for its database:
	// a missing database on a host where the source applies is an error
	// worth reporting, not a reason to skip.
	Applies(detect.OS) bool
	// Collect returns the installed packages. It must only read (never
	// execute anything or write) and should honour ctx for long reads.
	Collect(ctx context.Context, t target.Target) ([]collector.Package, error)
}

// Registry is an ordered set of Sources.
type Registry struct {
	sources []Source
}

// NewRegistry panics on duplicate names: that is a programming error, and
// duplicate keys would silently overwrite each other's status.
func NewRegistry(sources ...Source) *Registry {
	seen := map[string]bool{}
	for _, s := range sources {
		if seen[s.Name()] {
			panic(fmt.Sprintf("pkgsource: duplicate source name %q", s.Name()))
		}
		seen[s.Name()] = true
	}
	return &Registry{sources: sources}
}

// Default is every Source this agent build supports.
func Default() *Registry {
	return NewRegistry(Dpkg{})
}

// Applicable returns the sources that apply to o, in registry order.
func (r *Registry) Applicable(o detect.OS) []Source {
	var out []Source
	for _, s := range r.sources {
		if s.Applies(o) {
			out = append(out, s)
		}
	}
	return out
}

// Collect runs every applicable source against t and returns the combined
// packages plus one status per registered source: ok, error (with its
// message) or skipped (not applicable to o).
//
// A failing source never aborts the others or the snapshot. Its packages
// are dropped entirely rather than partially reported, so the server sees
// "unknown" for that ecosystem, never a truncated list it could mistake for
// removals. pkgs is nil when no source succeeded.
func (r *Registry) Collect(ctx context.Context, t target.Target, o detect.OS) (pkgs []collector.Package, status map[string]collector.CollectorStatus) {
	status = make(map[string]collector.CollectorStatus, len(r.sources))
	for _, s := range r.sources {
		if !s.Applies(o) {
			status[s.Name()] = collector.Skipped(fmt.Sprintf("not applicable to %s", describe(o)))
			continue
		}
		got, err := s.Collect(ctx, t)
		if err != nil {
			status[s.Name()] = collector.Failed(err)
			continue
		}
		// Stamp the ecosystem here so a source can't forget or misspell it.
		for i := range got {
			got[i].Ecosystem = s.Ecosystem()
		}
		if pkgs == nil {
			pkgs = []collector.Package{} // ok-but-empty serializes as [], not null
		}
		pkgs = append(pkgs, got...)
		status[s.Name()] = collector.OK()
	}
	return pkgs, status
}

func describe(o detect.OS) string {
	switch {
	case o.Family == detect.FamilyUnknown:
		return "undetected OS"
	case o.ID != "":
		return fmt.Sprintf("%s (%s)", o.Family, o.ID)
	default:
		return string(o.Family)
	}
}
