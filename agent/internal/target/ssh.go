package target

// Remote targets over SSH (DOMAIN_MODEL.md §4.2, Q3/Q4 resolved
// 2026-09-27). The agent reads a remote machine's files over SFTP,
// read-only, with its own key pair; it never opens a shell or runs a
// command on the remote machine. The recommended authorized_keys entry
// forces that on the remote side too:
//
//	restrict,command="/usr/lib/openssh/sftp-server -R" ssh-ed25519 AAAA... upkeep-agent
//
// Host keys are pinned: DialSSH refuses any key but the one the user
// confirmed in the dashboard. ProbeHostKey fetches the key a host presents
// (without authenticating) so it can be shown for confirmation.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Connection error codes, reported to the server per target (they match
// agent_hosts.last_error_code, migration 0012).
const (
	CodeHostKeyUnconfirmed = "host_key_unconfirmed"
	CodeHostKeyMismatch    = "host_key_mismatch"
	CodeAuthFailed         = "auth_failed"
	CodeUnreachable        = "unreachable"
	CodeSFTPFailed         = "sftp_failed"
)

// ConnError is a failed connection to a remote target.
type ConnError struct {
	Code string
	Err  error
	// HostKey is the key the host presented, if the handshake got that far.
	HostKey ssh.PublicKey
}

func (e *ConnError) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *ConnError) Unwrap() error { return e.Err }

// SSHConfig describes one remote target.
type SSHConfig struct {
	Ref      string
	Address  string // hostname or IP literal
	Port     int
	Username string
	// HostKey is the pinned host key; nil means none confirmed yet
	// (DialSSH then fails with CodeHostKeyUnconfirmed; use ProbeHostKey).
	HostKey ssh.PublicKey
	Signer  ssh.Signer
	// Timeout bounds the TCP connect and the SSH handshake (default 15s).
	Timeout time.Duration
}

func (c SSHConfig) addr() string { return net.JoinHostPort(c.Address, strconv.Itoa(c.Port)) }

func (c SSHConfig) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 15 * time.Second
}

// SSH is a connected remote target. It has no LiveProc: collectors that
// walk live process state (listeners, deleted libraries) report skipped.
// Its procfs files are still readable through ProcFS.
type SSH struct {
	ref    string
	client *ssh.Client
	sftp   *sftp.Client
	fsys   *sftpFS
}

func (s *SSH) Ref() string { return s.ref }
func (s *SSH) Mode() Mode  { return ModeSSH }
func (s *SSH) FS() fs.FS   { return s.fsys }

// ProcFS is the remote /proc, read file by file over SFTP.
func (s *SSH) ProcFS() fs.FS {
	sub, _ := fs.Sub(s.fsys, "proc") // "proc" is a valid path: no error
	return sub
}

// Close ends the SFTP session and the SSH connection.
func (s *SSH) Close() error {
	err := s.sftp.Close()
	if cerr := s.client.Close(); err == nil {
		err = cerr
	}
	return err
}

// hostKeyAlgorithms lists the signature algorithms to negotiate for a key
// type, so the host presents the key that was pinned (a host usually has
// several: ed25519, ecdsa, rsa) rather than whichever it prefers.
func hostKeyAlgorithms(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

// probeAlgorithms is the preference order when no key is pinned yet.
var probeAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

var errProbeDone = errors.New("host key captured")

// ProbeHostKey connects to the target and returns the host key it
// presents, aborting the handshake before authentication.
func ProbeHostKey(ctx context.Context, cfg SSHConfig) (ssh.PublicKey, error) {
	var presented ssh.PublicKey
	conf := &ssh.ClientConfig{
		User:              cfg.Username,
		HostKeyAlgorithms: probeAlgorithms,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			presented = key
			return errProbeDone
		},
		Timeout: cfg.timeout(),
	}
	conn, err := dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.timeout()))
	_, _, _, err = ssh.NewClientConn(conn, cfg.addr(), conf)
	if presented != nil {
		return presented, nil
	}
	return nil, &ConnError{Code: CodeUnreachable, Err: fmt.Errorf("ssh handshake: %w", err)}
}

// DialSSH connects to the target with the pinned host key and the agent's
// key, and opens an SFTP session.
func DialSSH(ctx context.Context, cfg SSHConfig) (*SSH, error) {
	if cfg.HostKey == nil {
		return nil, &ConnError{Code: CodeHostKeyUnconfirmed, Err: errors.New("no confirmed host key")}
	}
	var presented ssh.PublicKey
	mismatch := false
	conf := &ssh.ClientConfig{
		User:              cfg.Username,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(cfg.Signer)},
		HostKeyAlgorithms: hostKeyAlgorithms(cfg.HostKey.Type()),
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			presented = key
			if !bytes.Equal(key.Marshal(), cfg.HostKey.Marshal()) {
				mismatch = true
				return errors.New("host key does not match the confirmed key")
			}
			return nil
		},
		Timeout: cfg.timeout(),
	}
	conn, err := dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(cfg.timeout()))
	c, chans, reqs, err := ssh.NewClientConn(conn, cfg.addr(), conf)
	if err != nil {
		conn.Close()
		switch {
		case mismatch:
			return nil, &ConnError{Code: CodeHostKeyMismatch, Err: err, HostKey: presented}
		case presented == nil && strings.Contains(err.Error(), "no common algorithm"):
			// The host no longer offers the pinned key's type: as good as
			// a changed key, but there's no key to show. Probe for one.
			return nil, &ConnError{Code: CodeHostKeyMismatch, Err: err}
		case strings.Contains(err.Error(), "unable to authenticate"):
			return nil, &ConnError{Code: CodeAuthFailed, Err: err, HostKey: presented}
		default:
			return nil, &ConnError{Code: CodeUnreachable, Err: err, HostKey: presented}
		}
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(c, chans, reqs)
	sc, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		return nil, &ConnError{Code: CodeSFTPFailed, Err: err, HostKey: presented}
	}
	return &SSH{ref: cfg.Ref, client: client, sftp: sc, fsys: &sftpFS{c: sc}}, nil
}

func dial(ctx context.Context, cfg SSHConfig) (net.Conn, error) {
	d := net.Dialer{Timeout: cfg.timeout()}
	conn, err := d.DialContext(ctx, "tcp", cfg.addr())
	if err != nil {
		return nil, &ConnError{Code: CodeUnreachable, Err: err}
	}
	return conn, nil
}

// sftpFS is a read-only fs.FS over an SFTP session, rooted at the remote
// "/". It implements ReadDirFS, StatFS and ReadLinkFS. Unlike a local bind
// mount, absolute symlinks resolve on the remote side, against the
// remote root.
type sftpFS struct{ c *sftp.Client }

func remotePath(op, name string) (string, error) {
	// Backslashes are refused, as os.DirFS does on Windows: collectors
	// never use them, and fstest expects it on Windows.
	if !fs.ValidPath(name) || strings.Contains(name, `\`) {
		return "", &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return "/", nil
	}
	return "/" + name, nil
}

func pathErr(op, name string, err error) error {
	// pkg/sftp maps SSH_FX_NO_SUCH_FILE / PERMISSION_DENIED to
	// os.ErrNotExist / os.ErrPermission, so errors.Is works on these.
	return &fs.PathError{Op: op, Path: name, Err: err}
}

func (f *sftpFS) Open(name string) (fs.File, error) {
	p, err := remotePath("open", name)
	if err != nil {
		return nil, err
	}
	info, err := f.c.Stat(p)
	if err != nil {
		return nil, pathErr("open", name, err)
	}
	if info.IsDir() {
		return &sftpDir{fsys: f, name: name, path: p, info: info}, nil
	}
	file, err := f.c.Open(p)
	if err != nil {
		return nil, pathErr("open", name, err)
	}
	return &sftpFile{f: file, info: info}, nil
}

func (f *sftpFS) ReadDir(name string) ([]fs.DirEntry, error) {
	p, err := remotePath("readdir", name)
	if err != nil {
		return nil, err
	}
	infos, err := f.c.ReadDir(p) // lstat semantics: symlinks stay symlinks
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	out := make([]fs.DirEntry, 0, len(infos))
	for _, i := range infos {
		out = append(out, fs.FileInfoToDirEntry(i))
	}
	return out, nil // pkg/sftp returns them sorted by name
}

func (f *sftpFS) Stat(name string) (fs.FileInfo, error) {
	p, err := remotePath("stat", name)
	if err != nil {
		return nil, err
	}
	info, err := f.c.Stat(p)
	if err != nil {
		return nil, pathErr("stat", name, err)
	}
	return info, nil
}

func (f *sftpFS) Lstat(name string) (fs.FileInfo, error) {
	p, err := remotePath("lstat", name)
	if err != nil {
		return nil, err
	}
	info, err := f.c.Lstat(p)
	if err != nil {
		return nil, pathErr("lstat", name, err)
	}
	return info, nil
}

func (f *sftpFS) ReadLink(name string) (string, error) {
	p, err := remotePath("readlink", name)
	if err != nil {
		return "", err
	}
	t, err := f.c.ReadLink(p)
	if err != nil {
		return "", pathErr("readlink", name, err)
	}
	return t, nil
}

// sftpFile exposes only Read/Stat/Close. In particular it hides
// sftp.File.WriteTo, which trusts the stat size: procfs files report size
// 0 and would read as empty.
type sftpFile struct {
	f    *sftp.File
	info fs.FileInfo
}

func (s *sftpFile) Read(b []byte) (int, error) { return s.f.Read(b) }
func (s *sftpFile) Stat() (fs.FileInfo, error) { return s.info, nil }
func (s *sftpFile) Close() error               { return s.f.Close() }

type sftpDir struct {
	fsys    *sftpFS
	name    string
	path    string
	info    fs.FileInfo
	entries []fs.DirEntry
	read    bool
}

func (d *sftpDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: errors.New("is a directory")}
}
func (d *sftpDir) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *sftpDir) Close() error               { return nil }

func (d *sftpDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if !d.read {
		e, err := d.fsys.ReadDir(d.name)
		if err != nil {
			return nil, err
		}
		d.entries, d.read = e, true
	}
	if n <= 0 {
		out := d.entries
		d.entries = nil
		return out, nil
	}
	if len(d.entries) == 0 {
		return nil, io.EOF
	}
	if n > len(d.entries) {
		n = len(d.entries)
	}
	out := d.entries[:n]
	d.entries = d.entries[n:]
	return out, nil
}

// Compile-time checks.
var (
	_ Target         = (*SSH)(nil)
	_ ProcFiles      = (*SSH)(nil)
	_ fs.ReadDirFS   = (*sftpFS)(nil)
	_ fs.StatFS      = (*sftpFS)(nil)
	_ fs.ReadLinkFS  = (*sftpFS)(nil)
	_ fs.ReadDirFile = (*sftpDir)(nil)
)
