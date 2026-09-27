package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pippinmole/upkeep.sh/agent/internal/transport"
)

// loadOrEnroll returns existing credentials from disk, or performs
// one-time enrollment using SW_ENROLLMENT_TOKEN and persists the result.
func loadOrEnroll(client *transport.Client, credPath string) (storedCredentials, error) {
	if creds, ok := loadCredentials(credPath); ok {
		return creds, nil
	}

	token := os.Getenv("SW_ENROLLMENT_TOKEN")
	if token == "" {
		return storedCredentials{}, fmt.Errorf("no stored credentials at %s and SW_ENROLLMENT_TOKEN not set", credPath)
	}
	// The token is one-time: check the credentials can be saved before
	// spending it, or a read-only container without a data volume would
	// burn the token and then fail on every restart.
	if err := checkWritable(filepath.Dir(credPath)); err != nil {
		return storedCredentials{}, fmt.Errorf("data directory %s is not writable (mount a persistent volume there, e.g. -v upkeep-agent-data:%s): %w",
			filepath.Dir(credPath), filepath.Dir(credPath), err)
	}
	hostname, _ := os.Hostname()

	resp, err := client.Enroll(transport.EnrollRequest{
		EnrollmentToken: token, Hostname: hostname, Version: version, Platform: platform(),
	})
	if err != nil {
		return storedCredentials{}, err
	}
	creds := storedCredentials{AgentID: resp.AgentID, AgentSecret: resp.AgentSecret}
	if err := saveCredentials(credPath, creds); err != nil {
		return storedCredentials{}, err
	}
	return creds, nil
}

// checkWritable creates and removes a temp file in dir.
func checkWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".write-check-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}
