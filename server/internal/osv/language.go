package osv

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Language ecosystems (DOMAIN_MODEL.md §2.3 "As built (P2a, language
// ecosystems)").
//
// A language package has no distro and no release. Its advisory_affected
// rows have distro '' and release = the software_versions.ecosystem
// ("npm"), so one (distro, release, source_package) key never mixes two
// ecosystems' packages of the same name (npm "request" and PyPI
// "request"), and source_package is the name as software_versions stores
// it (purl.Map), so the matcher joins without translating.
//
// One record can list packages of several ecosystems (a GHSA for a
// project published to npm and PyPI) and then appears in each
// ecosystem's all.zip under the same id. advisories.id is the OSV id, so
// every language feed normalizes such a record to the same rows: the
// affected entries of *every* imported language ecosystem, not only its
// own. Whichever feed writes it last owns it (advisories.source); the
// other sees an unchanged content hash. The supported set is part of each
// language feed's fingerprint, so adding an ecosystem reloads the others.

// Languages maps each imported OSV language ecosystem (also its bucket
// directory) to its software_versions.ecosystem (the purl type).
var Languages = map[string]string{
	"npm": "npm",
}

// LanguageFor returns the software ecosystem of an imported OSV language
// ecosystem ("npm" -> "npm").
func LanguageFor(osvEcosystem string) (string, bool) {
	e, ok := Languages[osvEcosystem]
	return e, ok
}

// languageName maps an OSV package name to the stored name
// (purl.Map's form): npm "@scope/name" and Go module paths are the same
// in both.
func languageName(osvEcosystem, name string) string {
	return name
}

// IsMalicious reports an OSSF malicious-packages record (MAL-*). They are
// not imported yet: they flag a package as malware (every version), not
// a vulnerable version range, and need their own finding type.
func IsMalicious(id string) bool { return strings.HasPrefix(id, "MAL-") }

// FeedFingerprint identifies what one OSV directory's import depends on:
// the distro's supported releases, or for a language directory the set
// of imported language ecosystems (see above). A full import runs when it
// changes.
func FeedFingerprint(dir string, rels Releases) string {
	if _, ok := Languages[dir]; !ok {
		return rels.Fingerprint(DistroFor(dir))
	}
	keys := make([]string, 0, len(Languages))
	for k := range Languages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(fmt.Sprintf("v%d|languages|%s", NormalizeVersion, strings.Join(keys, ","))))
	return hex.EncodeToString(sum[:])
}

// ghsaAlias returns the record's GHSA id (its own, else the lowest GHSA
// alias), "" when it has none.
func ghsaAlias(id string, aliases []string) string {
	if strings.HasPrefix(id, "GHSA-") {
		return id
	}
	best := ""
	for _, a := range aliases {
		if strings.HasPrefix(a, "GHSA-") && (best == "" || a < best) {
			best = a
		}
	}
	return best
}
