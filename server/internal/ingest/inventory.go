package ingest

import (
	"slices"
	"strings"

	"github.com/pippinmole/upkeep.sh/server/internal/inventory"
)

// DefaultEcosystem is assumed for packages without an ecosystem field.
// Every agent that omits it is a dpkg-only agent.
const DefaultEcosystem = "deb"

// packageCollectorName is the collectors-map key that owns an ecosystem's
// packages: "<ecosystem>_packages" (e.g. "deb_packages"). See PROTOCOL.md.
func packageCollectorName(ecosystem string) string { return ecosystem + "_packages" }

// distroScoped lists ecosystems whose versions only mean something within
// one distro release (advisories are per release). Their interned rows are
// keyed by os.id + os.codename, so they need a known OS to be diffed.
// Add rpm/apk here when those sources land; ecosystems not listed (Windows
// programs, Homebrew, ...) are interned with an empty distro/release.
var distroScoped = map[string]bool{DefaultEcosystem: true}

// SkippedEcosystem records why a reported (or expected) ecosystem was not
// diffed on this push. Its open ranges are left exactly as they were.
type SkippedEcosystem struct {
	Ecosystem string
	Reason    string
}

// defaultPackage fills the fields older agents don't send:
//   - ecosystem "" → "deb"
//   - source "" → source = binary name, source_version = binary version,
//     marked inferred (a real source seen later overrides it on the
//     interned row)
//   - source set, source_version "" → source_version = binary version
//     (dpkg's "Source: foo" form)
func defaultPackage(p Package) (ecosystem string, it inventory.Item) {
	ecosystem = p.Ecosystem
	if ecosystem == "" {
		ecosystem = DefaultEcosystem
	}
	it = inventory.Item{Name: p.Name, Version: p.Version, Arch: p.Arch,
		Source: p.Source, SourceVersion: p.SourceVersion}
	if it.Source == "" {
		it.Source, it.SourceVersion, it.SourceInferred = p.Name, p.Version, true
	} else if it.SourceVersion == "" {
		it.SourceVersion = p.Version
	}
	return ecosystem, it
}

func validItem(it inventory.Item) bool {
	if it.Name == "" || it.Version == "" {
		return false
	}
	for _, f := range []string{it.Name, it.Version, it.Arch, it.Source, it.SourceVersion} {
		if strings.IndexByte(f, 0) >= 0 { // Postgres text can't hold NUL
			return false
		}
	}
	return true
}

// planInventory decides which ecosystems in this payload are authoritative
// and builds one canonical Set for each. Only these sets may open or close
// ranges; every other ecosystem's ranges are left untouched.
//
// Rules (docs/PROTOCOL.md "collectors"):
//
//  1. packages null or absent → nothing is authoritative.
//  2. collectors map present (current agents): ecosystem E is
//     authoritative iff collectors["E_packages"].status == "ok". That holds
//     even when no packages of E were reported (an ok-and-empty source
//     closes E's ranges). Packages of any other ecosystem are ignored.
//  3. collectors map absent (agents older than per-collector status):
//     those agents never pushed after a dpkg failure, so a non-empty
//     packages list is an ok "deb" source. An empty list is NOT treated as
//     authoritative: a Debian-like host with zero installed packages is
//     implausible, and closing every range on one odd push is the costly
//     mistake, so we skip it.
//  4. Distro-scoped ecosystems (deb) also need a known OS (os.id non-empty,
//     and collectors["os"] ok when the map is present), because the interned
//     key includes distro + release: diffing under an unknown distro would
//     close and reopen every range.
func planInventory(p SnapshotPayload) (sets []inventory.Set, skipped []SkippedEcosystem) {
	if p.Packages == nil {
		for _, eco := range okPackageEcosystems(p.Collectors) {
			skipped = append(skipped, SkippedEcosystem{eco, "collector ok but packages is null"})
		}
		return nil, skipped
	}

	byEco := map[string][]inventory.Item{}
	for _, pkg := range p.Packages {
		eco, it := defaultPackage(pkg)
		if !validItem(it) {
			continue
		}
		byEco[eco] = append(byEco[eco], it)
	}

	var authoritative []string
	if p.Collectors == nil {
		if len(p.Packages) == 0 {
			return nil, []SkippedEcosystem{{DefaultEcosystem, "legacy payload with empty packages"}}
		}
		for eco := range byEco {
			authoritative = append(authoritative, eco)
		}
	} else {
		authoritative = okPackageEcosystems(p.Collectors)
		for eco := range byEco {
			if !slices.Contains(authoritative, eco) {
				skipped = append(skipped, SkippedEcosystem{eco, "packages reported but " +
					packageCollectorName(eco) + " status is not ok"})
			}
		}
	}
	slices.Sort(authoritative)

	osOK := p.OS.ID != ""
	if p.Collectors != nil && p.Collectors[CollectorOS].Status != CollectorStatusOK {
		osOK = false
	}
	for _, eco := range authoritative {
		var distro, release string
		if distroScoped[eco] {
			if !osOK {
				skipped = append(skipped, SkippedEcosystem{eco, "os unknown (os collector not ok or os.id empty)"})
				continue
			}
			distro, release = p.OS.ID, p.OS.Codename
		}
		sets = append(sets, inventory.NewSet(eco, distro, release, byEco[eco]))
	}
	slices.SortFunc(skipped, func(a, b SkippedEcosystem) int { return strings.Compare(a.Ecosystem, b.Ecosystem) })
	return sets, skipped
}

// okPackageEcosystems returns, sorted, every ecosystem whose package
// collector reported status ok.
func okPackageEcosystems(collectors map[string]CollectorStatus) []string {
	var out []string
	for name, st := range collectors {
		eco, ok := strings.CutSuffix(name, "_packages")
		if ok && eco != "" && st.Status == CollectorStatusOK {
			out = append(out, eco)
		}
	}
	slices.Sort(out)
	return out
}
