// Package sshkey validates SSH public keys reported by agents: the agent's
// own key (shown in the dashboard for authorized_keys) and the host keys
// remote hosts present (pinned by the user). The server never uses these
// keys cryptographically; it stores and displays them, so validation is
// about shape: a known key type, base64 that decodes to an SSH wire-format
// blob naming the same type, and a sane size. Nothing else from the agent's
// line (options, comments) is kept.
package sshkey

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

// MaxLen bounds a key line (an RSA-8192 key is about 1.4 KB of base64).
const MaxLen = 4096

var knownTypes = map[string]bool{
	"ssh-ed25519":                        true,
	"ssh-rsa":                            true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

var ErrInvalid = errors.New("invalid ssh public key")

// Normalize parses "type base64 [comment]" and returns "type base64", or
// ErrInvalid.
func Normalize(line string) (string, error) {
	line = strings.TrimSpace(line)
	if line == "" || len(line) > MaxLen {
		return "", ErrInvalid
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || !knownTypes[fields[0]] {
		return "", ErrInvalid
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(blob) < 4 {
		return "", ErrInvalid
	}
	// The blob starts with the key type as an SSH string (uint32 length).
	n := binary.BigEndian.Uint32(blob)
	if uint64(n) > uint64(len(blob)-4) || string(blob[4:4+n]) != fields[0] {
		return "", ErrInvalid
	}
	return fields[0] + " " + fields[1], nil
}
