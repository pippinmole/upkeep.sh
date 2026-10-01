// Package osv parses OSV.dev records for the Debian, Ubuntu and Alpine
// ecosystems and the language ecosystems in Languages, and normalizes them
// into the advisory schema (migrations/0005, DOMAIN_MODEL.md §2.4): one
// Advisory per record, one Affected row per (release, source package,
// channel, introduced) range pair, for supported releases and imported
// language ecosystems only.
//
// It is pure: no I/O besides the HTTP client in client.go. Version strings
// are passed through untouched; comparing them is the matcher's job
// (server/internal/debversion, server/internal/apkversion, ...).
package osv

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Record is the subset of the OSV schema (https://ossf.github.io/osv-schema/)
// the normalizer reads. Fields not declared here (notably the large
// affected[].versions arrays) are skipped by the decoder.
type Record struct {
	ID        string     `json:"id"`
	Summary   string     `json:"summary"`
	Details   string     `json:"details"`
	Aliases   []string   `json:"aliases"`
	Upstream  []string   `json:"upstream"`
	Related   []string   `json:"related"`
	Published string     `json:"published"`
	Modified  string     `json:"modified"`
	Withdrawn string     `json:"withdrawn"`
	Severity  []Severity `json:"severity"`
	Affected  []Affected `json:"affected"`
	// GHSASeverity is a GitHub advisory's reviewed severity (record-level
	// database_specific.severity: "CRITICAL", "HIGH", "MODERATE", "LOW");
	// "" when absent or not a string.
	GHSASeverity string `json:"-"`

	// Undecoded source, kept to build the trimmed `raw` column.
	rawTop      map[string]json.RawMessage
	rawAffected []json.RawMessage
}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Affected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
		Purl      string `json:"purl"`
	} `json:"package"`
	Ranges            []Range           `json:"ranges"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific"`
	DatabaseSpecific  DatabaseSpecific  `json:"database_specific"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced   *string `json:"introduced"`
	Fixed        *string `json:"fixed"`
	LastAffected *string `json:"last_affected"`
	Limit        *string `json:"limit"`
}

type EcosystemSpecific struct {
	Urgency        string `json:"urgency"`         // Debian
	UbuntuPriority string `json:"ubuntu_priority"` // Ubuntu, per-package override
	Availability   string `json:"availability"`    // Ubuntu, e.g. "Available with Ubuntu Pro: ..."
}

type DatabaseSpecific struct {
	// USN records: per-CVE severities for this affected entry.
	CVEsMap *struct {
		CVEs []struct {
			ID       string     `json:"id"`
			Severity []Severity `json:"severity"`
		} `json:"cves"`
	} `json:"cves_map"`
}

// Parse decodes one OSV JSON record.
func Parse(data []byte) (*Record, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, err
	}
	var r Record
	for _, f := range []struct {
		key string
		dst any
	}{
		{"id", &r.ID},
		{"summary", &r.Summary},
		{"details", &r.Details},
		{"aliases", &r.Aliases},
		{"upstream", &r.Upstream},
		{"related", &r.Related},
		{"published", &r.Published},
		{"modified", &r.Modified},
		{"withdrawn", &r.Withdrawn},
		{"severity", &r.Severity},
		{"affected", &r.rawAffected},
	} {
		if v, ok := top[f.key]; ok {
			if err := json.Unmarshal(v, f.dst); err != nil {
				return nil, fmt.Errorf("osv %s: field %s: %w", r.ID, f.key, err)
			}
		}
	}
	if r.ID == "" {
		return nil, errors.New("osv record without id")
	}
	// database_specific is free-form per database: read the one field we
	// use and ignore anything else (a distro may put another shape there).
	if v, ok := top["database_specific"]; ok {
		var ds struct {
			Severity any `json:"severity"`
		}
		if json.Unmarshal(v, &ds) == nil {
			r.GHSASeverity, _ = ds.Severity.(string)
		}
	}
	r.Affected = make([]Affected, len(r.rawAffected))
	for i, raw := range r.rawAffected {
		if err := json.Unmarshal(raw, &r.Affected[i]); err != nil {
			return nil, fmt.Errorf("osv %s: affected[%d]: %w", r.ID, i, err)
		}
	}
	r.rawTop = top
	return &r, nil
}

// versions returns affected[i].versions, the explicit list of affected
// versions (decoded only when an entry has no usable range).
func (r *Record) versions(i int) ([]string, error) {
	var a struct {
		Versions []string `json:"versions"`
	}
	err := json.Unmarshal(r.rawAffected[i], &a)
	return a.Versions, err
}

// trimmedRaw re-encodes the record keeping only the affected entries at
// indexes keep, each without `versions` (unless listed in keepVersions:
// the entry matched by its versions list) and
// `ecosystem_specific.binaries`. Everything the normalizer reads is
// preserved, so the stored raw can be re-normalized for the releases that
// were supported when it was synced.
func (r *Record) trimmedRaw(keep []int, keepVersions map[int]bool) ([]byte, error) {
	out := make(map[string]json.RawMessage, len(r.rawTop))
	for k, v := range r.rawTop {
		out[k] = v
	}
	aff := make([]json.RawMessage, 0, len(keep))
	for _, i := range keep {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(r.rawAffected[i], &m); err != nil {
			return nil, err
		}
		if !keepVersions[i] {
			delete(m, "versions")
		}
		if es, ok := m["ecosystem_specific"]; ok {
			var esm map[string]json.RawMessage
			if json.Unmarshal(es, &esm) == nil {
				delete(esm, "binaries")
				b, err := json.Marshal(esm)
				if err != nil {
					return nil, err
				}
				m["ecosystem_specific"] = b
			}
		}
		b, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		aff = append(aff, b)
	}
	b, err := json.Marshal(aff)
	if err != nil {
		return nil, err
	}
	out["affected"] = b
	return json.Marshal(out)
}

func parseTime(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil, err
	}
	t = t.UTC()
	return &t, nil
}
