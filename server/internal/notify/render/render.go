// Package render turns notify events into short human-readable text: the
// one-line titles, plain-text bodies and bulleted lists shared by the
// channel types that write for people (ntfy, email). Channel-specific
// presentation (ntfy priorities and tags, email headers and layout) stays
// in each channel's package.
package render

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pippinmole/upkeep.sh/server/internal/notify"
)

// IsKEVOrCritical reports whether a finding is known exploited or critical.
func IsKEVOrCritical(f *notify.Finding) bool {
	return f.KEV || strings.EqualFold(f.Severity, "critical")
}

// Resolved reports whether an event is an alert resolving.
func Resolved(e notify.Event) bool { return e.Type == notify.EventAlertResolved }

// Title is a one-line description of an event: the alert's title and
// host, e.g. "Port 22/tcp is listening on web-1", "KEV CVE-2024-3094 in
// xz-utils on web-1", "Resolved: Port 22/tcp is listening on web-1".
func Title(e notify.Event) string {
	s := e.Type
	if e.Alert != nil && e.Alert.Title != "" {
		s = e.Alert.Title
	}
	if e.Host != nil {
		s += " on " + HostName(*e.Host)
	}
	if Resolved(e) {
		s = "Resolved: " + s
	}
	return s
}

// Body is a few plain-text lines of detail about an event: for a
// vulnerability the package and version, fix, severity/KEV/EPSS; for other
// alerts their details (addresses, versions, error, last seen); then since
// when it fired.
func Body(e notify.Event) string {
	var lines []string
	if e.Finding != nil {
		lines = findingLines(e)
	} else if e.Alert != nil {
		lines = detailLines(e.Alert.Details)
	}
	if a := e.Alert; a != nil {
		switch {
		case Resolved(e) && a.ResolvedAt != nil:
			lines = append(lines, "Fired "+stamp(a.FiredAt)+", resolved "+stamp(*a.ResolvedAt)+".")
		case !a.FiredAt.IsZero():
			lines = append(lines, "Firing since "+stamp(a.FiredAt)+".")
		}
	}
	if len(lines) == 0 {
		return Title(e)
	}
	return strings.Join(lines, "\n")
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func findingLines(e notify.Event) []string {
	var lines []string
	f := e.Finding
	pkg := f.SourcePackage
	if pkg == "" && len(f.Packages) > 0 {
		pkg = f.Packages[0]
	}
	if pkg != "" {
		line := "Package: " + pkg
		if f.InstalledVersion != "" {
			line += " " + f.InstalledVersion
		}
		if bins := otherPackages(pkg, f.Packages); bins != "" {
			line += " (" + bins + ")"
		}
		lines = append(lines, line)
	}
	if f.ImageID != "" {
		img := f.ImageID
		if len(f.ImageRefs) > 0 {
			img = strings.Join(f.ImageRefs, ", ")
		}
		line := "Image: " + img
		if len(f.Containers) > 0 {
			line += " (containers: " + strings.Join(f.Containers, ", ") + ")"
		}
		lines = append(lines, line)
	}
	switch {
	case Resolved(e) && f.ImageID != "":
		lines = append(lines, "No longer present in an image a container on the host uses.")
	case Resolved(e):
		lines = append(lines, "No longer present on the host.")
	case f.FixedVersion != nil && *f.FixedVersion != "":
		fix := "Fix: upgrade to " + *f.FixedVersion
		if f.FixChannel != nil && *f.FixChannel != "" {
			fix += " (" + *f.FixChannel + ")"
		}
		lines = append(lines, fix)
	default:
		lines = append(lines, "Fix: none available yet")
	}
	risk := []string{"Severity: " + orUnknown(f.Severity)}
	if f.KEV {
		risk = append(risk, "known exploited (CISA KEV)")
	}
	if f.EPSS != nil {
		risk = append(risk, fmt.Sprintf("EPSS %.1f%%", *f.EPSS*100))
	}
	return append(lines, strings.Join(risk, ", "))
}

// detailLabels are the alert detail keys rendered for people, in order
// (store/alertrules_eval.go writes them).
var detailLabels = []struct{ key, label string }{
	{"addresses", "Listening on"},
	{"processes", "Process"},
	{"versions", "Installed"},
	{"os", "OS"},
	{"packages", "Packages"},
	{"collector", "Collector"},
	{"error", "Error"},
	{"last_seen_at", "Last seen"},
}

func detailLines(raw json.RawMessage) []string {
	var d map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &d) != nil {
		return nil
	}
	var lines []string
	for _, l := range detailLabels {
		var s string
		switch v := d[l.key].(type) {
		case []any:
			parts := make([]string, 0, len(v))
			for _, x := range v {
				parts = append(parts, fmt.Sprint(x))
			}
			s = strings.Join(parts, ", ")
		case string:
			s = v
			if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
				s = stamp(t)
			}
		case nil:
		default:
			s = fmt.Sprint(v)
		}
		if s != "" {
			lines = append(lines, l.label+": "+s)
		}
	}
	return lines
}

// List lists up to max events, one "• title" line each, ending in
// "…and N more" when there are more.
func List(events []notify.Event, max int) string {
	if len(events) == 0 {
		return "No events."
	}
	var b strings.Builder
	for i, e := range events {
		if i == max {
			fmt.Fprintf(&b, "…and %d more", len(events)-max)
			break
		}
		b.WriteString("• " + Title(e))
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

// CommonURL is the link for a multi-event message: the events' URL if they
// all share one, else the dashboard root they point into (SW_DASHBOARD_URL
// + "/dashboard"); "" when events carry no links.
func CommonURL(events []notify.Event) string {
	var first string
	same := true
	for _, e := range events {
		if e.URL == "" {
			continue
		}
		if first == "" {
			first = e.URL
		} else if e.URL != first {
			same = false
		}
	}
	if first == "" || same {
		return first
	}
	if i := strings.Index(first, "/dashboard/"); i >= 0 {
		return first[:i] + "/dashboard"
	}
	return ""
}

func otherPackages(src string, pkgs []string) string {
	var out []string
	for _, p := range pkgs {
		if p != src {
			out = append(out, p)
		}
	}
	if len(out) > 3 {
		out = append(out[:3], fmt.Sprintf("+%d more", len(out)-3))
	}
	return strings.Join(out, ", ")
}

// HostName is a host's label, or its hostname when it has none.
func HostName(h notify.Host) string {
	if h.Label != nil && *h.Label != "" {
		return *h.Label
	}
	return h.Hostname
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Truncate cuts s to at most max bytes on a rune boundary, ending in "…".
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
