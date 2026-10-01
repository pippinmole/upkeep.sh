package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeOSRelease(t *testing.T, content string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "sys", "kernel")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "osrelease"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCollectKernelRelease(t *testing.T) {
	for content, want := range map[string]string{
		"6.8.0-45-generic\n":    "6.8.0-45-generic",
		"6.1.0-18-amd64":        "6.1.0-18-amd64",
		"6.12.48+deb13-amd64\n": "6.12.48+deb13-amd64",
	} {
		got, err := CollectKernelRelease(os.DirFS(writeOSRelease(t, content)))
		if err != nil || got != want {
			t.Errorf("CollectKernelRelease(%q) = %q, %v; want %q", content, got, err, want)
		}
	}
	for _, bad := range []string{"", "\n", "two words"} {
		if _, err := CollectKernelRelease(os.DirFS(writeOSRelease(t, bad))); err == nil {
			t.Errorf("CollectKernelRelease(%q): want error", bad)
		}
	}
	if _, err := CollectKernelRelease(os.DirFS(t.TempDir())); err == nil || !strings.Contains(err.Error(), "osrelease") {
		t.Errorf("missing file: err = %v", err)
	}
}
