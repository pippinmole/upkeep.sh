package detect

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// Identity is what the server uses to recognise a host across agent
// reinstalls (DOMAIN_MODEL.md §4.3), plus its current hostname.
type Identity struct {
	MachineID string // Linux /etc/machine-id
	Hostname  string
}

// LinuxIdentity reads /etc/machine-id and /etc/hostname from the target's
// filesystem. The hostname is read from the host's file rather than
// os.Hostname() so it describes the target, not the agent's own process
// (which, for a remote target, would be a different machine entirely).
//
// A missing /etc/hostname is not an error (some minimal images lack it);
// a missing or empty machine-id is, because the host can't be identified
// without it.
func LinuxIdentity(fsys fs.FS) (Identity, error) {
	var id Identity

	hn, err := firstLine(fsys, "etc/hostname")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return id, fmt.Errorf("read etc/hostname: %w", err)
	}
	id.Hostname = hn

	mid, err := firstLine(fsys, "etc/machine-id")
	if err != nil {
		return id, fmt.Errorf("read etc/machine-id: %w", err)
	}
	if mid == "" {
		// systemd leaves it empty (or "uninitialized") in images meant to
		// generate one on first boot.
		return id, errors.New("etc/machine-id is empty")
	}
	if mid == "uninitialized" {
		return id, errors.New("etc/machine-id is uninitialized")
	}
	id.MachineID = mid
	return id, nil
}

func firstLine(fsys fs.FS, name string) (string, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if sc.Scan() {
		return strings.TrimSpace(sc.Text()), nil
	}
	return "", sc.Err()
}
