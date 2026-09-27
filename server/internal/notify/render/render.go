// Package render turns notify events into short human-readable text: the
// one-line titles, plain-text bodies and bulleted lists shared by the
// channel types that write for people (ntfy, email). Channel-specific
// presentation (ntfy priorities and tags, email headers and layout) stays
// in each channel's package.
package render

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/pippinmole/upkeep.sh/server/internal/notify"
)

// IsKEVOrCritical reports whether a finding is known exploited or critical.
func IsKEVOrCritical(f *notify.Finding) bool {
	return f.KEV || strings.EqualFold(f.Severity, "critical")
}

var findingVerb = map[string]string{
	notify.EventFindingOpened:   "opened",
	notify.EventFindingReopened: "reopened",
	notify.EventFindingResolved: "resolved",
}

// Title is a one-line description of an event, e.g. "KEV CVE-2024-3094
// opened on web-1", "Critical CVE-2024-1 reopened on db",
// `Agent "edge" stopped reporting`.
func Title(e notify.Event) string {
	switch {
	case e.Finding != nil:
		f := e.Finding
		prefix := ""
		switch {
		case f.KEV && e.Type != notify.EventFindingResolved:
			prefix = "KEV "
		case f.Severity != "" && e.Type != notify.EventFindingResolved:
			prefix = capitalize(f.Severity) + " "
		}
		verb := findingVerb[e.Type]
		if verb == "" {
			verb = e.Type
		}
		s := prefix + f.VulnKey + " " + verb
		if e.Host != nil {
			s += " on " + HostName(*e.Host)
		}
		return s
	case e.Agent != nil:
		if e.Type == notify.EventAgentStale {
			return fmt.Sprintf("Agent %q stopped reporting", e.Agent.Name)
		}
		return fmt.Sprintf("Agent %q is reporting again", e.Agent.Name)
	}
	return e.Type
}

// Body is a few plain-text lines of detail about an event (package and
// version, fix, severity/KEV/EPSS; or an agent's last check-in and hosts).
func Body(e notify.Event) string {
	var lines []string
	switch {
	case e.Finding != nil:
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
		switch {
		case e.Type == notify.EventFindingResolved:
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
		lines = append(lines, strings.Join(risk, ", "))
	case e.Agent != nil:
		if e.Agent.LastSeenAt != nil {
			lines = append(lines, "Last seen "+e.Agent.LastSeenAt.UTC().Format("2006-01-02 15:04 UTC"))
		}
		if len(e.Agent.Hosts) > 0 {
			names := make([]string, len(e.Agent.Hosts))
			for i, h := range e.Agent.Hosts {
				names[i] = HostName(h)
			}
			lines = append(lines, "Hosts: "+strings.Join(names, ", "))
		}
		if e.Type == notify.EventAgentStale {
			lines = append(lines, "Its hosts aren't being scanned until it reports again.")
		}
	}
	if len(lines) == 0 {
		return Title(e)
	}
	return strings.Join(lines, "\n")
}

// List lists up to max events, one "• title (package)" line each, ending
// in "…and N more" when there are more.
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
		if e.Finding != nil && e.Finding.SourcePackage != "" {
			b.WriteString(" (" + e.Finding.SourcePackage + ")")
		}
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

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
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
