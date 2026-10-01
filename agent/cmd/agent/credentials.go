package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pippinmole/upkeep.sh/agent/internal/transport"
)

// storedCredentials is SW_DATA_DIR/credentials.json.
type storedCredentials struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
}

// loadCredentials reads credentials.json; ok is false when it is missing
// or unusable (the agent then enrolls).
func loadCredentials(path string) (storedCredentials, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return storedCredentials{}, false
	}
	var c storedCredentials
	if err := json.Unmarshal(b, &c); err != nil || c.AgentID == "" || c.AgentSecret == "" {
		return storedCredentials{}, false
	}
	return c, true
}

// saveCredentials writes credentials.json atomically: a temp file in the
// same directory (mode 0600), fsynced, then renamed over the old file, and
// the directory fsynced. A crash leaves either the old or the new file,
// never a truncated one.
func saveCredentials(path string, c storedCredentials) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".credentials-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Make the rename itself durable. Not supported everywhere (Windows);
	// the rename has happened either way.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// rotateCredentials gets a new secret from the server and persists it
// before returning it. If persisting fails the new secret is discarded and
// the caller keeps the old one: the server still accepts it for its grace
// window and keeps asking for a rotation, so the next cycle retries. Disk
// and memory never disagree, so a restart can't lose the working secret.
func rotateCredentials(client *transport.Client, credPath string, cur storedCredentials) (storedCredentials, error) {
	resp, err := client.RotateCredentials(cur.AgentID, cur.AgentSecret)
	if err != nil {
		return cur, err
	}
	next := storedCredentials{AgentID: cur.AgentID, AgentSecret: resp.AgentSecret}
	if err := saveCredentials(credPath, next); err != nil {
		return cur, fmt.Errorf("persist rotated credentials (keeping the old secret, will retry): %w", err)
	}
	return next, nil
}
