package cvefeeds

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// testdata/kev.json: three real entries from the 2026.09.25 catalog.
// testdata/epss.csv.gz: the first four rows of the 2026-09-26 file.

func TestParseKEV(t *testing.T) {
	f, err := os.Open("testdata/kev.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cat, err := ParseKEV(f)
	if err != nil {
		t.Fatal(err)
	}
	if cat.Version != "2026.09.25" || len(cat.Entries) != 3 {
		t.Fatalf("version %q, %d entries", cat.Version, len(cat.Entries))
	}
	e := cat.Entries[0]
	if e.CVE != "CVE-2026-59310" || !e.Ransomware ||
		!e.DateAdded.Equal(time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)) ||
		e.DueDate == nil || !e.DueDate.Equal(time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("entry 0 = %+v", e)
	}
	if cat.Entries[1].Ransomware {
		t.Error("Unknown ransomware use must be false")
	}
}

func TestParseKEVRejectsEmptyOrTruncated(t *testing.T) {
	for _, in := range []string{
		`{"catalogVersion":"x","count":0,"vulnerabilities":[]}`,
		`{"catalogVersion":"x","count":5,"vulnerabilities":[{"cveID":"CVE-1-1","dateAdded":"2026-01-01"}]}`,
		`{"catalogVersion":"x","vulnerabilities":[`,
	} {
		if _, err := ParseKEV(strings.NewReader(in)); err == nil {
			t.Errorf("%s: expected error", in)
		}
	}
}

func TestEPSSReader(t *testing.T) {
	f, err := os.Open("testdata/epss.csv.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := NewEPSSReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Header.ModelVersion != "v2026.06.15" ||
		!r.Header.ScoreDate.Equal(time.Date(2026, 9, 26, 12, 0, 22, 0, time.UTC)) {
		t.Errorf("header = %+v", r.Header)
	}
	var rows []EPSSScore
	for {
		s, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, s)
	}
	if len(rows) != 4 || rows[1] != (EPSSScore{"CVE-1999-0002", "0.27858", "0.98033"}) {
		t.Errorf("rows = %+v", rows)
	}
}

func TestEPSSReaderRejectsBadHeader(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("cve,epss,percentile\nCVE-1,0.1,0.2\n"))
	_ = gz.Close()
	if _, err := NewEPSSReader(&buf); err == nil {
		t.Error("expected error without score_date")
	}
}
