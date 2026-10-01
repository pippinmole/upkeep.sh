package collector

import (
	"bufio"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"
)

// systemdUnitDirs are systemd's system unit search paths, highest
// precedence first (systemd.unit(5)). A unit name is taken from the first
// directory that has it, as systemd does. On merged-/usr hosts lib/ and
// usr/lib/ are the same directory; the first-wins rule makes that harmless.
var systemdUnitDirs = []string{
	"etc/systemd/system",
	"run/systemd/system",
	"usr/local/lib/systemd/system",
	"lib/systemd/system",
	"usr/lib/systemd/system",
}

// ErrNoSystemd means the target has none of systemd's unit directories:
// the collector does not apply (skipped, not failed).
var ErrNoSystemd = errors.New("no systemd unit directories found")

// Unit types indexed: services are reported; sockets, timers and paths
// only decide whether a service is started on demand ("manual").
var indexedUnitSuffixes = []string{".service", ".socket", ".timer", ".path"}

type unitEntry struct {
	file   string // fs path of the unit file ("" when masked)
	masked bool
}

type unitIndex struct {
	units   map[string]unitEntry         // name (incl. templates "foo@.service") -> first found
	aliases map[string]string            // alias name -> real unit name
	wanted  map[string]bool              // names symlinked into *.wants/*.requires/*.upholds
	dropins map[string]map[string]string // unit name -> drop-in file name -> fs path (highest precedence)
	// unreadableDirs counts unit directories that exist but could not be
	// listed (permission denied): the index is then incomplete.
	unreadableDirs int
}

// CollectSystemdServices lists the target's systemd services from unit
// files alone (no D-Bus, no systemctl): see DOMAIN_MODEL.md §4.8.
//
//   - start_mode: "masked" (unit file is a symlink to /dev/null, or
//     empty); "auto" (symlinked into some unit's .wants/, .requires/ or
//     .upholds/ directory, in /etc by `systemctl enable` or in /lib by the
//     vendor: it is started at boot); "manual" (not wanted itself, but a
//     same-named .socket, .timer or .path unit is, so it starts on demand;
//     attrs.activated_by names it); "static" (no [Install] section, so it
//     can't be enabled and only runs as another unit's dependency);
//     otherwise "disabled".
//   - state: "running" if any process's cgroup is the service's
//     (units, from ProcessUnits), else "stopped". units == nil (no live
//     procfs) leaves state empty.
//   - display_name from Description=, binary_path from the first
//     ExecStart= command, run_as from User= ("root" when unset, as for any
//     system service; empty with attrs.dynamic_user for DynamicUser=yes).
//     Drop-ins (<unit>.d/*.conf, and the template's for instances) are
//     applied in file-name order.
//
// Template instances ("getty@tty1.service") are reported when an instance
// is wanted or running; bare templates ("getty@.service") are not units
// and are not reported. Services seen only in cgroups with no unit file
// (transient units) are not reported either.
//
// Permission errors don't fail the collector: the agent may run
// unprivileged, and some generator output is root-only (netplan writes
// /run/systemd/system/*.service mode 0640). A service whose unit file or
// drop-in can't be read is still reported, with what the index alone
// tells (name, unit_path, and start_mode when it is auto or manual;
// start_mode and run_as are left empty when they depend on the file) and
// the unreadable files' paths in attrs.unreadable. A unit directory that
// can't be listed is skipped and the result reported as truncated, so the
// server treats the list as additive only rather than reading the
// services it would have held as removed. Other errors still fail.
func CollectSystemdServices(fsys fs.FS, units map[int]string) ([]Service, bool, error) {
	idx, found, err := indexUnits(fsys)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, ErrNoSystemd
	}

	running := map[string]bool{}
	for _, u := range units {
		running[u] = true
	}

	names := map[string]bool{}
	for name := range idx.units {
		if strings.HasSuffix(name, ".service") && !isTemplate(name) {
			names[name] = true
		}
	}
	addInstance := func(name string) {
		if tmpl, ok := templateOf(name); ok && !isTemplate(name) {
			if _, ok := idx.units[tmpl]; ok {
				names[name] = true
			}
		}
	}
	for name := range idx.wanted {
		addInstance(name)
	}
	for name := range running {
		addInstance(name)
	}

	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	slices.Sort(sorted)
	truncated := idx.unreadableDirs > 0
	if len(sorted) > MaxServices {
		sorted, truncated = sorted[:MaxServices], true
	}

	out := make([]Service, 0, len(sorted))
	for _, name := range sorted {
		svc, err := idx.service(fsys, name)
		if err != nil {
			return nil, false, err
		}
		if units != nil {
			svc.State = "stopped"
			if running[name] {
				svc.State = "running"
			}
		}
		out = append(out, svc)
	}
	return out, truncated, nil
}

func isTemplate(name string) bool { return strings.Contains(name, "@.") }

// templateOf returns "foo@.service" for "foo@bar.service".
func templateOf(name string) (string, bool) {
	at := strings.IndexByte(name, '@')
	dot := strings.LastIndexByte(name, '.')
	if at < 0 || dot < at {
		return "", false
	}
	return name[:at+1] + name[dot:], true
}

func hasIndexedSuffix(name string) bool {
	for _, s := range indexedUnitSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

func indexUnits(fsys fs.FS) (*unitIndex, bool, error) {
	idx := &unitIndex{
		units:   map[string]unitEntry{},
		aliases: map[string]string{},
		wanted:  map[string]bool{},
		dropins: map[string]map[string]string{},
	}
	found := false
	var permErr error
	for _, dir := range systemdUnitDirs {
		entries, err := fs.ReadDir(fsys, dir)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case errors.Is(err, fs.ErrPermission):
			idx.unreadableDirs++
			permErr = err
			continue
		case err != nil:
			return nil, false, err
		}
		found = true
		for _, e := range entries {
			name := e.Name()
			p := path.Join(dir, name)
			switch {
			case e.IsDir() && (strings.HasSuffix(name, ".wants") || strings.HasSuffix(name, ".requires") || strings.HasSuffix(name, ".upholds")):
				deps, err := fs.ReadDir(fsys, p)
				if err != nil {
					continue
				}
				for _, d := range deps {
					if hasIndexedSuffix(d.Name()) {
						idx.wanted[d.Name()] = true
					}
				}
			case e.IsDir() && strings.HasSuffix(name, ".d"):
				unit := strings.TrimSuffix(name, ".d")
				if !hasIndexedSuffix(unit) {
					continue
				}
				confs, err := fs.ReadDir(fsys, p)
				if err != nil {
					continue
				}
				for _, c := range confs {
					if !strings.HasSuffix(c.Name(), ".conf") {
						continue
					}
					if idx.dropins[unit] == nil {
						idx.dropins[unit] = map[string]string{}
					}
					if _, ok := idx.dropins[unit][c.Name()]; !ok {
						idx.dropins[unit][c.Name()] = path.Join(p, c.Name())
					}
				}
			case hasIndexedSuffix(name):
				if _, seen := idx.units[name]; seen {
					continue
				}
				if _, seen := idx.aliases[name]; seen {
					continue
				}
				entry, alias := resolveUnitFile(fsys, dir, name, e)
				if alias != "" {
					idx.aliases[name] = alias
					continue
				}
				idx.units[name] = entry
			}
		}
	}
	if !found && permErr != nil {
		// Unit directories exist but none could be read: nothing to report.
		return nil, false, permErr
	}
	// A wanted alias enables the unit it points to.
	for name := range idx.wanted {
		if resolved, ok := idx.aliases[name]; ok {
			idx.wanted[resolved] = true
		}
	}
	return idx, found, nil
}

// resolveUnitFile classifies one unit-directory entry: a regular file; a
// symlink to /dev/null (masked); a symlink to a file of the same name
// elsewhere (a linked unit: re-rooted under the target, since an absolute
// link resolves against the agent's root otherwise); or a symlink to a
// different name (an alias, returned as alias).
func resolveUnitFile(fsys fs.FS, dir, name string, e fs.DirEntry) (entry unitEntry, alias string) {
	p := path.Join(dir, name)
	if e.Type()&fs.ModeSymlink == 0 {
		if info, err := e.Info(); err == nil && info.Size() == 0 {
			return unitEntry{masked: true}, ""
		}
		return unitEntry{file: p}, ""
	}
	target, err := fs.ReadLink(fsys, p)
	if err != nil {
		return unitEntry{file: p}, ""
	}
	if target == "/dev/null" {
		return unitEntry{masked: true}, ""
	}
	if base := path.Base(target); base != name {
		return unitEntry{}, base
	}
	if path.IsAbs(target) {
		return unitEntry{file: strings.TrimPrefix(path.Clean(target), "/")}, ""
	}
	return unitEntry{file: path.Clean(path.Join(dir, target))}, ""
}

// service builds the report for one service name.
func (idx *unitIndex) service(fsys fs.FS, name string) (Service, error) {
	svc := Service{Manager: "systemd", Name: name}
	entry, ok := idx.units[name]
	tmpl, isInstance := templateOf(name)
	if !ok && isInstance {
		entry = idx.units[tmpl]
	}
	if entry.masked || (isInstance && idx.units[tmpl].masked) {
		svc.StartMode = "masked"
		return svc, nil
	}

	// Unreadable (permission denied) files are skipped and listed in
	// attrs.unreadable; any other read error fails the collector.
	var unreadable []string
	readConf := func(conf *unitConf, file string) (bool, error) {
		err := conf.read(fsys, file)
		if errors.Is(err, fs.ErrPermission) {
			unreadable = append(unreadable, "/"+file)
			return false, nil
		}
		return err == nil, err
	}

	var conf unitConf
	mainRead, err := readConf(&conf, entry.file)
	if err != nil {
		return svc, err
	}
	hasInstall := conf.hasInstall
	// Drop-ins: the template's first, then the instance's, each in file-name order.
	for _, unit := range []string{tmpl, name} {
		if unit == "" {
			continue
		}
		files := idx.dropins[unit]
		keys := make([]string, 0, len(files))
		for k := range files {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if _, err := readConf(&conf, files[k]); err != nil {
				return svc, err
			}
		}
	}

	svc.DisplayName = conf.description
	if len(conf.execStart) > 0 {
		svc.BinaryPath = execBinary(conf.execStart[0])
	}
	attrs := map[string]any{"unit_path": "/" + entry.file}
	if len(unreadable) > 0 {
		attrs["unreadable"] = unreadable
	}
	switch {
	case conf.user != "":
		svc.RunAs = conf.user
	case conf.dynamicUser:
		attrs["dynamic_user"] = true
	case len(unreadable) == 0:
		svc.RunAs = "root"
	}
	// Otherwise an unread file may set User=: leave run_as unknown.

	// The trigger units that would start this service: foo.socket for
	// foo.service, and for an instance its template's (an Accept=yes
	// foo.socket spawns foo@<connection>.service).
	base := strings.TrimSuffix(name, ".service")
	if isInstance {
		base = strings.TrimSuffix(tmpl, "@.service")
	}
	switch {
	case idx.wanted[name]:
		svc.StartMode = "auto"
	default:
		for _, suffix := range []string{".socket", ".timer", ".path"} {
			trigger := base + suffix
			if idx.wanted[trigger] && !idx.units[trigger].masked {
				svc.StartMode = "manual"
				attrs["activated_by"] = trigger
				break
			}
		}
		if svc.StartMode == "" && mainRead {
			// Without the unit file, disabled vs static is unknown.
			if hasInstall {
				svc.StartMode = "disabled"
			} else {
				svc.StartMode = "static"
			}
		}
	}
	svc.Attrs = attrs
	return svc, nil
}

// unitConf accumulates the settings we report across a unit file and its
// drop-ins, in load order (later assignments override).
type unitConf struct {
	description string
	execStart   []string
	user        string
	dynamicUser bool
	hasInstall  bool // main file only: [Install] in drop-ins is ignored
}

func (c *unitConf) read(fsys fs.FS, file string) error {
	f, err := fsys.Open(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // a dangling link: report what we know
	} else if err != nil {
		return err
	}
	defer f.Close()
	isDropin := strings.HasSuffix(file, ".conf")

	section := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var cont strings.Builder
	for sc.Scan() {
		line := sc.Text()
		if strings.HasSuffix(line, "\\") {
			cont.WriteString(strings.TrimSuffix(line, "\\"))
			cont.WriteByte(' ')
			continue
		}
		if cont.Len() > 0 {
			cont.WriteString(line)
			line = cont.String()
			cont.Reset()
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			if section == "Install" && !isDropin {
				c.hasInstall = true
			}
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch section + "." + key {
		case "Unit.Description":
			c.description = val
		case "Service.ExecStart":
			if val == "" {
				c.execStart = nil
			} else {
				c.execStart = append(c.execStart, val)
			}
		case "Service.User":
			c.user = val
		case "Service.DynamicUser":
			c.dynamicUser = parseBool(val)
		}
	}
	return sc.Err()
}

func parseBool(v string) bool {
	switch strings.ToLower(v) {
	case "1", "yes", "true", "on":
		return true
	}
	return false
}

// execBinary returns the executable of an ExecStart= command line: the
// first word, after systemd's special prefixes (@ - : + !) and quotes.
func execBinary(cmd string) string {
	cmd = strings.TrimLeft(cmd, "@-:+!")
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if q := cmd[0]; q == '"' || q == '\'' {
		if end := strings.IndexByte(cmd[1:], q); end >= 0 {
			return cmd[1 : end+1]
		}
		return strings.Trim(cmd, `"'`)
	}
	if sp := strings.IndexAny(cmd, " \t"); sp >= 0 {
		return cmd[:sp]
	}
	return cmd
}
