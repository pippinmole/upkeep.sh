package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// sshKeyComment is appended to the public key shown in the dashboard.
const sshKeyComment = "upkeep-agent"

// loadOrCreateSSHKey returns the agent's SSH key for remote targets. The
// private key stays in the data directory (or the file the operator
// mounted, SW_SSH_KEY_FILE) and is never sent anywhere; only the public
// half is reported to the server. A key the operator supplied is never
// generated or overwritten: if it's missing, that's an error.
func loadOrCreateSSHKey(path string, generate bool) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		signer, err := ssh.ParsePrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w (passphrase-protected keys are not supported)", path, err)
		}
		return signer, nil
	case !errors.Is(err, fs.ErrNotExist) || !generate:
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, sshKeyComment)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, pem.EncodeToMemory(block)); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// authorizedKeyLine is the public key as an authorized_keys line.
func authorizedKeyLine(s ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " " + sshKeyComment
}

// writeFileAtomic writes a 0600 file via a temp file and rename, so a
// crash never leaves a truncated key behind.
func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
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
	if err = f.Chmod(0o600); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
