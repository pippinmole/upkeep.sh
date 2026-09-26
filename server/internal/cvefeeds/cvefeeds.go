// Package cvefeeds parses the per-CVE enrichment feeds stored in `cves`:
// the CISA Known Exploited Vulnerabilities catalog and FIRST EPSS scores.
package cvefeeds

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// KEVMirrorURL is CISA's own GitHub publication of the same catalog
	// (github.com/cisagov/kev-data). cisa.gov sits behind Akamai, which
	// answers some networks with a blanket 403 "Access Denied" regardless
	// of User-Agent; the sync falls back to this.
	KEVMirrorURL   = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
	DefaultEPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)

// KEVEntry is one catalog entry, reduced to what `cves` stores.
type KEVEntry struct {
	CVE        string
	DateAdded  time.Time
	DueDate    *time.Time
	Ransomware bool // knownRansomwareCampaignUse == "Known"
}

// KEVCatalog is the parsed catalog.
type KEVCatalog struct {
	Version string // catalogVersion, e.g. "2026.09.25"
	Entries []KEVEntry
}

// ParseKEV decodes the KEV JSON feed. It fails on an empty catalog so a
// truncated download can't clear every KEV flag.
func ParseKEV(r io.Reader) (KEVCatalog, error) {
	var doc struct {
		CatalogVersion  string `json:"catalogVersion"`
		Count           int    `json:"count"`
		Vulnerabilities []struct {
			CVEID      string `json:"cveID"`
			DateAdded  string `json:"dateAdded"`
			DueDate    string `json:"dueDate"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return KEVCatalog{}, fmt.Errorf("kev: %w", err)
	}
	if len(doc.Vulnerabilities) == 0 {
		return KEVCatalog{}, errors.New("kev: empty catalog")
	}
	if doc.Count != 0 && doc.Count != len(doc.Vulnerabilities) {
		return KEVCatalog{}, fmt.Errorf("kev: count %d but %d entries", doc.Count, len(doc.Vulnerabilities))
	}
	cat := KEVCatalog{Version: doc.CatalogVersion, Entries: make([]KEVEntry, 0, len(doc.Vulnerabilities))}
	for _, v := range doc.Vulnerabilities {
		added, err := time.Parse(time.DateOnly, v.DateAdded)
		if err != nil {
			return KEVCatalog{}, fmt.Errorf("kev %s: dateAdded: %w", v.CVEID, err)
		}
		e := KEVEntry{CVE: strings.TrimSpace(v.CVEID), DateAdded: added, Ransomware: strings.EqualFold(v.Ransomware, "Known")}
		if v.DueDate != "" {
			if due, err := time.Parse(time.DateOnly, v.DueDate); err == nil {
				e.DueDate = &due
			}
		}
		cat.Entries = append(cat.Entries, e)
	}
	return cat, nil
}

// EPSSScore is one CSV row. Score and Percentile are kept as the decimal
// text from the feed (Postgres casts them to numeric), so no float
// rounding is introduced.
type EPSSScore struct {
	CVE        string
	Score      string
	Percentile string
}

// EPSSHeader is the feed's leading comment line.
type EPSSHeader struct {
	ModelVersion string
	ScoreDate    time.Time
}

// EPSSReader streams a gzip-compressed EPSS CSV:
//
//	#model_version:v2026.06.15,score_date:2026-09-26T12:00:22Z
//	cve,epss,percentile
//	CVE-1999-0001,0.03351,0.88243
type EPSSReader struct {
	Header EPSSHeader
	gz     *gzip.Reader
	csv    *csv.Reader
}

func NewEPSSReader(r io.Reader) (*EPSSReader, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("epss: %w", err)
	}
	br := bufio.NewReader(gz)
	first, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("epss: header: %w", err)
	}
	var h EPSSHeader
	for _, kv := range strings.Split(strings.TrimPrefix(strings.TrimSpace(first), "#"), ",") {
		k, v, _ := strings.Cut(kv, ":")
		switch k {
		case "model_version":
			h.ModelVersion = v
		case "score_date":
			if h.ScoreDate, err = time.Parse(time.RFC3339, v); err != nil {
				return nil, fmt.Errorf("epss: score_date: %w", err)
			}
		}
	}
	if h.ScoreDate.IsZero() {
		return nil, fmt.Errorf("epss: no score_date in %q", first)
	}
	cr := csv.NewReader(br)
	cr.FieldsPerRecord = 3
	cr.ReuseRecord = true
	cols, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("epss: columns: %w", err)
	}
	if cols[0] != "cve" || cols[1] != "epss" || cols[2] != "percentile" {
		return nil, fmt.Errorf("epss: unexpected columns %v", cols)
	}
	return &EPSSReader{Header: h, gz: gz, csv: cr}, nil
}

// Next returns the next row, or io.EOF.
func (e *EPSSReader) Next() (EPSSScore, error) {
	rec, err := e.csv.Read()
	if err != nil {
		return EPSSScore{}, err
	}
	return EPSSScore{CVE: rec[0], Score: rec[1], Percentile: rec[2]}, nil
}

func (e *EPSSReader) Close() error { return e.gz.Close() }
