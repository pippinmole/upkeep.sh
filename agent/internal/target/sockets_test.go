package target

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// shortTempDir keeps socket paths under the 104/108-byte sun_path limit
// (t.TempDir is long on macOS).
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "sk") //nolint:usetesting // t.TempDir is too long for sun_path on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func listen(t *testing.T, root, rel string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
}

// A recursive host mount: /run's sockets are visible under the host root.
func TestReachableSocketsRecursiveMount(t *testing.T) {
	host := shortTempDir(t)
	listen(t, host, "run/docker.sock")
	listen(t, host, "run/dbus/system_bus_socket")
	listen(t, host, "run/user/1000/podman/podman.sock")
	listen(t, host, "run/foo/bar.sock") // not in the list: found by the walk
	listen(t, host, "var/snap/lxd/common/lxd/unix.socket")
	// var/run -> /run, absolute: must resolve against the host root and
	// count once, as run/docker.sock.
	if err := os.MkdirAll(filepath.Join(host, "var"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/run", filepath.Join(host, "var/run")); err != nil {
		t.Fatal(err)
	}

	l := NewLocal(host, "/proc")
	got := l.ReachableSockets("/var/run/docker.sock") // the usual opt-in: a container path
	want := []string{
		"run/dbus/system_bus_socket",
		"run/docker.sock",
		"run/foo/bar.sock",
		"run/user/1000/podman/podman.sock",
		"var/snap/lxd/common/lxd/unix.socket",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}

	// An opt-in pointed at the socket under the host root isn't counted.
	got = l.ReachableSockets(filepath.Join(host, "run/docker.sock"))
	if len(got) != len(want)-1 {
		t.Errorf("opt-in under the host root still reported: %v", got)
	}
}

// The non-recursive mount: /host/run is an empty mountpoint directory.
func TestReachableSocketsNonRecursive(t *testing.T) {
	host := shortTempDir(t)
	for _, d := range []string{"run", "var"} {
		if err := os.MkdirAll(filepath.Join(host, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/run", filepath.Join(host, "var/run")); err != nil {
		t.Fatal(err)
	}
	if got := NewLocal(host, "/proc").ReachableSockets(""); len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

func TestReachableSocketsBareMetal(t *testing.T) {
	if got := NewLocal("/", "/proc").ReachableSockets(""); got != nil {
		t.Errorf("bare metal: got %v, want nil", got)
	}
}

func TestResolveUnder(t *testing.T) {
	host := t.TempDir()
	if err := os.MkdirAll(filepath.Join(host, "run/lock"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(host, "var"), 0o755); err != nil {
		t.Fatal(err)
	}
	for target, link := range map[string]string{
		"/run":        "var/run",
		"../run/lock": "var/lock",
		"loop":        "loop",
	} {
		if err := os.Symlink(target, filepath.Join(host, link)); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]string{
		"var/run/lock": "run/lock",
		"var/lock":     "run/lock",
		"run":          "run",
	}
	for in, want := range cases {
		if got, ok := resolveUnder(host, in); !ok || got != want {
			t.Errorf("resolveUnder(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"missing", "var/run/missing", "loop"} {
		if _, ok := resolveUnder(host, in); ok {
			t.Errorf("resolveUnder(%q): want not ok", in)
		}
	}
}
