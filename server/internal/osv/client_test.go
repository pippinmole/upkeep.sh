package osv

import (
	"context"
	"crypto/md5" //nolint:gosec // GCS x-goog-hash integrity check, not security
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A first attempt that hangs mid-body must be abandoned by the stall
// watchdog and retried; the file from the successful attempt is verified.
func TestDownloadAllRetriesStall(t *testing.T) {
	old := StallTimeout
	StallTimeout = 200 * time.Millisecond
	defer func() { StallTimeout = old }()

	body := strings.Repeat("x", 4096)
	sum := md5.Sum([]byte(body)) //nolint:gosec // GCS x-goog-hash integrity check, not security
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Debian/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", "4096")
		w.Header().Set("X-Goog-Hash", "crc32c=AAAA==,md5="+base64.StdEncoding.EncodeToString(sum[:]))
		w.Header().Set("ETag", `"e1"`)
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(body[:100]))
			w.(http.Flusher).Flush()
			<-r.Context().Done() // hang until the client gives up
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL}
	start := time.Now()
	path, etag, size, err := c.DownloadAll(context.Background(), "Debian", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	if size != 4096 || etag != `"e1"` || calls.Load() != 2 {
		t.Errorf("size %d etag %s calls %d", size, etag, calls.Load())
	}
	if time.Since(start) > 30*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
}

func TestDownloadAllMD5Mismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Goog-Hash", "md5=AAAAAAAAAAAAAAAAAAAAAA==")
		_, _ = w.Write([]byte("zip"))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL}
	if _, _, _, err := c.downloadOnce(context.Background(), "Debian", t.TempDir()); err == nil || !strings.Contains(err.Error(), "md5") {
		t.Fatalf("err = %v", err)
	}
}
