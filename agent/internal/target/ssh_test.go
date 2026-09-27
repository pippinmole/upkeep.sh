package target

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io/fs"
	"net"
	"strconv"
	"testing"
	"testing/fstest"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// sshServer is an in-process SSH server that only serves the sftp
// subsystem, backed by an in-memory filesystem.
type sshServer struct {
	addr     string
	port     int
	hostKey  ssh.Signer
	handlers sftp.Handlers
}

func startSSHServer(t *testing.T, user string, clientKey ssh.PublicKey) *sshServer {
	t.Helper()
	srv := &sshServer{hostKey: newSigner(t), handlers: sftp.InMemHandler()}
	conf := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == user && bytes.Equal(k.Marshal(), clientKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	conf.AddHostKey(srv.hostKey)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv.addr = "127.0.0.1"
	srv.port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.serve(c, conf)
		}
	}()
	return srv
}

func (s *sshServer) serve(c net.Conn, conf *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(c, conf)
	if err != nil {
		c.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, in, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range in {
				ok := req.Type == "subsystem" && len(req.Payload) > 4 && string(req.Payload[4:]) == "sftp"
				_ = req.Reply(ok, nil)
				if ok {
					rs := sftp.NewRequestServer(ch, s.handlers)
					_ = rs.Serve()
					ch.Close()
				}
			}
		}()
	}
}

// seed writes files onto the server through a separate (writable) session.
func (s *sshServer) seed(t *testing.T, user string, key ssh.Signer, files map[string]string, links map[string]string) {
	t.Helper()
	c, err := ssh.Dial("tcp", net.JoinHostPort(s.addr, strconv.Itoa(s.port)), &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.FixedHostKey(s.hostKey.PublicKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sc, err := sftp.NewClient(c)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	for name, body := range files {
		if err := sc.MkdirAll(pathDir(name)); err != nil {
			t.Fatal(err)
		}
		f, err := sc.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	for link, to := range links {
		if err := sc.Symlink(to, link); err != nil {
			t.Fatal(err)
		}
	}
}

func pathDir(p string) string {
	for i := len(p) - 1; i > 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "/"
}

func TestSSHTarget(t *testing.T) {
	ctx := context.Background()
	agentKey := newSigner(t)
	srv := startSSHServer(t, "upkeep", agentKey.PublicKey())
	srv.seed(t, "upkeep", agentKey, map[string]string{
		"/etc/os-release":            "ID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\n",
		"/etc/hostname":              "db-1\n",
		"/proc/sys/kernel/osrelease": "6.8.0-45-generic\n",
	}, map[string]string{"/etc/alias-release": "/etc/os-release"})

	cfg := SSHConfig{Ref: "r1", Address: srv.addr, Port: srv.port, Username: "upkeep", Signer: agentKey, Timeout: 5 * time.Second}

	// Probe: the key the host presents, without authenticating.
	key, err := ProbeHostKey(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.Marshal(), srv.hostKey.PublicKey().Marshal()) {
		t.Fatal("probe returned a different key")
	}

	code := func(err error) string {
		var ce *ConnError
		if errors.As(err, &ce) {
			return ce.Code
		}
		return "<not a ConnError: " + err.Error() + ">"
	}

	// No confirmed key: refused before connecting.
	if _, err := DialSSH(ctx, cfg); code(err) != CodeHostKeyUnconfirmed {
		t.Fatalf("unpinned: %v", err)
	}

	// Pinned key doesn't match: refused, and the presented key is reported.
	wrong := cfg
	wrong.HostKey = newSigner(t).PublicKey()
	_, err = DialSSH(ctx, wrong)
	var ce *ConnError
	if !errors.As(err, &ce) || ce.Code != CodeHostKeyMismatch || ce.HostKey == nil ||
		!bytes.Equal(ce.HostKey.Marshal(), srv.hostKey.PublicKey().Marshal()) {
		t.Fatalf("mismatch: %v", err)
	}

	// Right host, wrong client key.
	badAuth := cfg
	badAuth.HostKey = key
	badAuth.Signer = newSigner(t)
	if _, err := DialSSH(ctx, badAuth); code(err) != CodeAuthFailed {
		t.Fatalf("bad auth: %v", err)
	}

	// Nothing listening.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	down := cfg
	down.Port, down.HostKey = closedPort, key
	if _, err := DialSSH(ctx, down); code(err) != CodeUnreachable {
		t.Fatalf("unreachable: %v", err)
	}

	cfg.HostKey = key
	tgt, err := DialSSH(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tgt.Close()
	if tgt.Ref() != "r1" || tgt.Mode() != ModeSSH {
		t.Fatalf("ref/mode: %s %s", tgt.Ref(), tgt.Mode())
	}
	fsys := tgt.FS()
	b, err := fs.ReadFile(fsys, "etc/os-release")
	if err != nil || !bytes.Contains(b, []byte("jammy")) {
		t.Fatalf("read os-release: %q %v", b, err)
	}
	if _, err := fs.ReadFile(fsys, "etc/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if l, err := fs.ReadLink(fsys, "etc/alias-release"); err != nil || l != "/etc/os-release" {
		t.Fatalf("readlink: %q %v", l, err)
	}
	entries, err := fs.ReadDir(fsys, "etc")
	if err != nil || len(entries) != 3 {
		t.Fatalf("readdir: %v %v", entries, err)
	}
	for _, e := range entries {
		if e.Name() == "alias-release" && e.Type()&fs.ModeSymlink == 0 {
			t.Error("readdir followed a symlink; want lstat semantics")
		}
	}
	if err := fstest.TestFS(fsys, "etc/os-release", "etc/hostname"); err != nil {
		t.Errorf("fstest: %v", err)
	}

	procFS, ok := ProcFSOf(tgt)
	if !ok {
		t.Fatal("ssh target has no procfs files")
	}
	if b, err := fs.ReadFile(procFS, "sys/kernel/osrelease"); err != nil || string(b) != "6.8.0-45-generic\n" {
		t.Fatalf("proc read: %q %v", b, err)
	}
	if _, ok := ProcRootOf(tgt); ok {
		t.Error("ssh target must not claim live procfs")
	}
}
