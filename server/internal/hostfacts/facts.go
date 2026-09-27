package hostfacts

import (
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"
)

// LinuxFacts is the validated shape of snapshots.facts for Linux hosts
// (DOMAIN_MODEL.md §4.5: the long tail of per-OS scalars and small lists,
// stored per snapshot rather than as range tables). Ingest decodes the
// payload's facts block into it, keeps only members whose collector
// reported ok, clamps sizes, and stores the re-encoded result, so the
// column never holds unvalidated agent JSON. Windows and macOS get their
// own structs alongside their collectors.
type LinuxFacts struct {
	NeedsRestart       *NeedsRestart       `json:"needs_restart,omitempty"`
	UnattendedUpgrades *UnattendedUpgrades `json:"unattended_upgrades,omitempty"`
}

// NeedsRestart: processes still mapping a deleted shared library (collector
// "deleted_libs").
type NeedsRestart struct {
	Processes           []DeletedLibProcess `json:"processes"`
	Truncated           bool                `json:"truncated,omitempty"`
	UnreadableProcesses int                 `json:"unreadable_processes"`
}

type DeletedLibProcess struct {
	PID       int      `json:"pid"`
	Name      string   `json:"name"`
	Unit      string   `json:"unit,omitempty"`
	Libraries []string `json:"libraries"`
}

// UnattendedUpgrades: Debian/Ubuntu automatic-update state (collector
// "unattended_upgrades").
type UnattendedUpgrades struct {
	PackageInstalled    *bool  `json:"package_installed,omitempty"`
	UpdatePackageLists  string `json:"update_package_lists,omitempty"`
	UnattendedUpgrade   string `json:"unattended_upgrade,omitempty"`
	Enabled             bool   `json:"enabled"`
	LastAptUpdate       string `json:"last_apt_update,omitempty"`
	LastAptUpdateSource string `json:"last_apt_update_source,omitempty"`
	LastUnattendedRun   string `json:"last_unattended_run,omitempty"`
}

// Server-side caps; generous relative to the agent's own, which are the
// real limit. They bound what a misbehaving agent can store.
const (
	maxDeletedLibProcesses   = 500
	maxDeletedLibsPerProcess = 50
)

// ValidateLinuxFacts decodes a payload facts block. needsRestartOK and
// unattendedOK say whether each member's collector reported ok; members
// whose collector didn't are dropped. It returns the canonical JSON to
// store ("{}" when nothing survives) and the decoded struct. Malformed
// JSON yields "{}" and the error, which ingest logs without rejecting the
// push.
func ValidateLinuxFacts(raw json.RawMessage, needsRestartOK, unattendedOK bool) ([]byte, LinuxFacts, error) {
	var f LinuxFacts
	if len(raw) == 0 || string(raw) == "null" {
		return []byte("{}"), f, nil
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return []byte("{}"), LinuxFacts{}, err
	}
	if !needsRestartOK {
		f.NeedsRestart = nil
	}
	if !unattendedOK {
		f.UnattendedUpgrades = nil
	}
	if nr := f.NeedsRestart; nr != nil {
		if nr.Processes == nil {
			nr.Processes = []DeletedLibProcess{}
		}
		if len(nr.Processes) > maxDeletedLibProcesses {
			nr.Processes, nr.Truncated = nr.Processes[:maxDeletedLibProcesses], true
		}
		kept := nr.Processes[:0]
		for _, p := range nr.Processes {
			if p.PID <= 0 {
				continue
			}
			p.Name = Clip(p.Name, 64)
			p.Unit = Clip(p.Unit, 256)
			if len(p.Libraries) > maxDeletedLibsPerProcess {
				p.Libraries = p.Libraries[:maxDeletedLibsPerProcess]
			}
			libs := make([]string, 0, len(p.Libraries))
			for _, l := range p.Libraries {
				if l = Clip(l, 1024); l != "" {
					libs = append(libs, l)
				}
			}
			p.Libraries = libs
			kept = append(kept, p)
		}
		nr.Processes = kept
		if nr.UnreadableProcesses < 0 {
			nr.UnreadableProcesses = 0
		}
	}
	if uu := f.UnattendedUpgrades; uu != nil {
		uu.UpdatePackageLists = Clip(uu.UpdatePackageLists, 32)
		uu.UnattendedUpgrade = Clip(uu.UnattendedUpgrade, 32)
		uu.LastAptUpdate = validTime(uu.LastAptUpdate)
		uu.LastUnattendedRun = validTime(uu.LastUnattendedRun)
		switch uu.LastAptUpdateSource {
		case "update-success-stamp", "lists":
		default:
			uu.LastAptUpdateSource = ""
		}
		if uu.LastAptUpdate == "" {
			uu.LastAptUpdateSource = ""
		}
	}
	b, err := json.Marshal(f)
	if err != nil {
		return []byte("{}"), LinuxFacts{}, err
	}
	return b, f, nil
}

func validTime(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Clip drops NUL bytes and invalid UTF-8 (Postgres text accepts neither),
// trims space, and cuts s to at most n bytes without splitting a rune.
func Clip(s string, n int) string {
	s = strings.TrimSpace(strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), ""))
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
