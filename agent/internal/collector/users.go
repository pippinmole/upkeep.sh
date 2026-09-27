package collector

import (
	"bufio"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
)

// AdminGroups are the groups whose members are flagged admin: sudo
// (Debian/Ubuntu), wheel (RHEL/Arch), admin (old Ubuntu) and adm (reads
// system logs; Ubuntu's first user is in it).
var AdminGroups = []string{"sudo", "wheel", "adm", "admin"}

// nonLoginShells are shells that refuse an interactive login.
var nonLoginShells = map[string]bool{
	"nologin": true, "false": true, "true": true, "sync": true, "shutdown": true, "halt": true,
}

// CollectLocalUsers lists local accounts from etc/passwd, with group
// memberships from etc/group (primary group by gid, supplementary by the
// member lists). Password hashes live in /etc/shadow, which is never read.
// Only local files are consulted: directory-service (LDAP/SSSD) accounts
// are out of scope. Users are sorted by name and capped at MaxUsers.
func CollectLocalUsers(fsys fs.FS) ([]User, bool, error) {
	groupsByGID := map[int]string{}
	members := map[string][]string{} // user -> supplementary groups
	if err := readColonFile(fsys, "etc/group", 4, func(f []string) {
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			return
		}
		if _, ok := groupsByGID[gid]; !ok {
			groupsByGID[gid] = f[0]
		}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members[m] = append(members[m], f[0])
			}
		}
	}); err != nil {
		return nil, false, err
	}

	var users []User
	seen := map[string]bool{}
	if err := readColonFile(fsys, "etc/passwd", 7, func(f []string) {
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil || seen[f[0]] {
			return
		}
		seen[f[0]] = true
		u := User{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]}
		primary := groupsByGID[gid]
		if primary != "" {
			u.Groups = append(u.Groups, primary)
		}
		supp := slices.Clone(members[u.Name])
		slices.Sort(supp)
		for _, g := range slices.Compact(supp) {
			if g != primary {
				u.Groups = append(u.Groups, g)
			}
		}
		// An empty shell field means /bin/sh to login(1).
		u.LoginShell = u.Shell == "" || !nonLoginShells[path.Base(u.Shell)]
		u.Admin = uid == 0 || slices.ContainsFunc(u.Groups, func(g string) bool { return slices.Contains(AdminGroups, g) })
		users = append(users, u)
	}); err != nil {
		return nil, false, err
	}

	slices.SortFunc(users, func(a, b User) int { return strings.Compare(a.Name, b.Name) })
	truncated := false
	if len(users) > MaxUsers {
		users, truncated = users[:MaxUsers], true
	}
	return users, truncated, nil
}

// readColonFile calls fn with the fields of every well-formed line of a
// colon-separated database (passwd/group). Comments, NIS "+"/"-" entries
// and lines with fewer than minFields fields are skipped.
func readColonFile(fsys fs.FS, name string, minFields int, fn func([]string)) error {
	f, err := fsys.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || line[0] == '#' || line[0] == '+' || line[0] == '-' {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < minFields || fields[0] == "" {
			continue
		}
		fn(fields)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	return nil
}
