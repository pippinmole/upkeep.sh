package sbom

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/pippinmole/upkeep.sh/server/internal/purl"
)

// Entry is one package as an in-process generator reports it (server-side
// Syft, internal/imagescan): its purl and the paths it was found at.
type Entry struct {
	PURL  string   `json:"purl"`
	Paths []string `json:"paths,omitempty"`
}

// FromEntries builds a Document from a package list produced without a
// document in between. Purls and paths get the same treatment as Parse
// (unparseable purls are Skipped, paths cleaned per type); the OS is osr,
// else what the distro packages' qualifiers say. Packages come out
// sorted by purl, so the list is stable for the same input.
func FromEntries(toolName, toolVersion string, created time.Time, osr purl.OSRelease, entries []Entry) *Document {
	doc := &Document{ToolName: toolName, ToolVersion: toolVersion, Created: created, OS: osr}
	entries = slices.Clone(entries)
	slices.SortStableFunc(entries, func(a, b Entry) int { return cmp.Compare(a.PURL, b.PURL) })
	for _, e := range entries {
		u, err := purl.Parse(strings.TrimSpace(e.PURL))
		if err != nil {
			doc.Skipped++
			continue
		}
		doc.Packages = append(doc.Packages, Package{PURL: u, Paths: cleanPaths(u.Type, e.Paths)})
	}
	if doc.OS.ID == "" {
		doc.OS = osFromPURLs(doc.Packages)
	}
	return doc
}
