package collector

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"
)

const (
	aptConfDir         = "etc/apt/apt.conf.d"
	aptUpdateStamp     = "var/lib/apt/periodic/update-success-stamp"
	aptListsDir        = "var/lib/apt/lists"
	unattendedRunStamp = "var/lib/apt/periodic/unattended-upgrades-stamp"
)

// CollectUnattendedUpgrades reports Debian/Ubuntu automatic-update state
// from files only:
//
//   - APT::Periodic::Update-Package-Lists and ::Unattended-Upgrade from
//     every file in /etc/apt/apt.conf.d, in the order apt reads them
//     (lexical), later values overriding earlier ones. On a stock system
//     they are set by 20auto-upgrades; 50unattended-upgrades holds the
//     origins policy, not the on/off switch. /etc/apt/apt.conf (the
//     legacy single file) is read last, as apt does.
//   - whether the unattended-upgrades package is installed, from the
//     package inventory (pkgs; nil when it wasn't collected).
//   - the last successful apt update: the mtime of APT's
//     update-success-stamp (touched by apt.systemd.daily and by
//     `apt update` via the apt-daily hook), falling back to the mtime of
//     /var/lib/apt/lists (changes whenever lists are refreshed).
//   - the last unattended-upgrades run: its periodic stamp's mtime.
//
// Only the flat "APT::Periodic::Key "value";" form is understood, which is
// what Debian and Ubuntu ship and what the documentation shows; the
// nested-braces form is not parsed.
func CollectUnattendedUpgrades(fsys fs.FS, pkgs []Package) (UnattendedUpgrades, error) {
	var u UnattendedUpgrades

	var confFiles []string
	entries, err := fs.ReadDir(fsys, aptConfDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return u, err
	}
	for _, e := range entries {
		// apt ignores files with other characters than alnum, _ - . and
		// ones ending in .disabled/.dpkg-* etc; approximate that.
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") || strings.Contains(n, ".dpkg-") ||
			strings.HasSuffix(n, ".disabled") || strings.HasSuffix(n, ".bak") || strings.HasSuffix(n, "~") {
			continue
		}
		confFiles = append(confFiles, path.Join(aptConfDir, n))
	}
	slices.Sort(confFiles)
	confFiles = append(confFiles, "etc/apt/apt.conf")
	for _, f := range confFiles {
		if err := readAptPeriodic(fsys, f, &u); err != nil {
			return u, err
		}
	}

	if pkgs != nil {
		installed := slices.ContainsFunc(pkgs, func(p Package) bool {
			return p.Name == "unattended-upgrades" && p.Ecosystem == "deb"
		})
		u.PackageInstalled = &installed
	}
	u.Enabled = intervalOn(u.UnattendedUpgrade) && (u.PackageInstalled == nil || *u.PackageInstalled)

	if t, ok := mtime(fsys, aptUpdateStamp); ok {
		u.LastAptUpdate, u.LastAptUpdateSource = t, "update-success-stamp"
	} else if t, ok := mtime(fsys, aptListsDir); ok {
		u.LastAptUpdate, u.LastAptUpdateSource = t, "lists"
	}
	if t, ok := mtime(fsys, unattendedRunStamp); ok {
		u.LastUnattendedRun = t
	}
	return u, nil
}

// intervalOn reports whether an APT::Periodic interval value enables the
// job: a number of days other than 0, or a duration like "1d"/"12h".
func intervalOn(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && strings.TrimLeft(v, "0") != "" && v != "false" && v != "no"
}

func mtime(fsys fs.FS, name string) (string, bool) {
	info, err := fs.Stat(fsys, name)
	if err != nil {
		return "", false
	}
	return info.ModTime().UTC().Format(time.RFC3339), true
}

func readAptPeriodic(fsys fs.FS, name string, u *UnattendedUpgrades) error {
	f, err := fsys.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	inBlockComment := false
	for sc.Scan() {
		line := sc.Text()
		if inBlockComment {
			end := strings.Index(line, "*/")
			if end < 0 {
				continue
			}
			line, inBlockComment = line[end+2:], false
		}
		if start := strings.Index(line, "/*"); start >= 0 {
			if end := strings.Index(line[start:], "*/"); end >= 0 {
				line = line[:start] + line[start+end+2:]
			} else {
				line, inBlockComment = line[:start], true
			}
		}
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		for _, stmt := range strings.Split(line, ";") {
			key, val, ok := strings.Cut(strings.TrimSpace(stmt), " ")
			if !ok {
				continue
			}
			val = strings.Trim(strings.TrimSpace(val), `"`)
			switch strings.ToLower(key) {
			case "apt::periodic::update-package-lists":
				u.UpdatePackageLists = val
			case "apt::periodic::unattended-upgrade":
				u.UnattendedUpgrade = val
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	return nil
}
