package collector

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeProc builds a procfs-shaped directory tree for tests.
type fakeProc struct {
	t    *testing.T
	root string
}

func newFakeProc(t *testing.T) *fakeProc {
	t.Helper()
	return &fakeProc{t: t, root: t.TempDir()}
}

func (p *fakeProc) file(rel, content string) {
	p.t.Helper()
	full := filepath.Join(p.root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		p.t.Fatal(err)
	}
}

func (p *fakeProc) symlink(rel, target string) {
	p.t.Helper()
	full := filepath.Join(p.root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		p.t.Fatal(err)
	}
	if err := os.Symlink(target, full); err != nil {
		p.t.Fatal(err)
	}
}

// process adds /proc/<pid> with comm, cgroup and maps files.
func (p *fakeProc) process(pid, comm, cgroup, maps string) {
	p.file(pid+"/comm", comm+"\n")
	p.file(pid+"/cgroup", cgroup)
	p.file(pid+"/maps", maps)
}
