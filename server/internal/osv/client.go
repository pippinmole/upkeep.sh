package osv

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// DefaultBaseURL is OSV's public GCS bucket. Layout per ecosystem
// directory ("Debian", "Ubuntu"):
//
//	<dir>/all.zip           every record, one <id>.json per zip entry
//	<dir>/modified_id.csv   "<modified RFC3339>,<id>" per record, newest first
//	<dir>/<id>.json         one record
//
// Per-release directories ("Debian:12/all.zip") exist but are no longer
// updated (last modified 2024-10), so only the top-level ones are used.
const DefaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// ErrNotFound is returned by Get for a record that no longer exists.
var ErrNotFound = errors.New("osv: record not found")

type Client struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string
}

func (c *Client) url(parts ...string) string {
	esc := make([]string, len(parts))
	for i, p := range parts {
		esc[i] = url.PathEscape(p)
	}
	return strings.TrimRight(c.BaseURL, "/") + "/" + strings.Join(esc, "/")
}

func (c *Client) get(ctx context.Context, u, etag string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	return hc.Do(req)
}

// StallTimeout aborts a download attempt that receives no bytes for this
// long (GCS connections occasionally hang mid-body; seen in testing).
var StallTimeout = 90 * time.Second

// DownloadAll streams <dir>/all.zip into a new temp file in tmpDir and
// verifies its length and MD5 (GCS x-goog-hash). A stalled or failed
// attempt is retried up to 3 times. The caller removes the file. Nothing
// is buffered in memory beyond io.Copy's buffer.
func (c *Client) DownloadAll(ctx context.Context, dir, tmpDir string) (path, etag string, size int64, err error) {
	for attempt := 1; ; attempt++ {
		path, etag, size, err = c.downloadOnce(ctx, dir, tmpDir)
		if err == nil || attempt == 3 || ctx.Err() != nil {
			return path, etag, size, err
		}
		select {
		case <-time.After(time.Duration(attempt) * 5 * time.Second):
		case <-ctx.Done():
			return "", "", 0, ctx.Err()
		}
	}
}

func (c *Client) downloadOnce(ctx context.Context, dir, tmpDir string) (path, etag string, size int64, err error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	errStalled := fmt.Errorf("download %s/all.zip: no data for %s", dir, StallTimeout)
	watchdog := time.AfterFunc(StallTimeout, func() { cancel(errStalled) })
	defer watchdog.Stop()

	resp, err := c.get(ctx, c.url(dir, "all.zip"), "")
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", 0, fmt.Errorf("GET %s/all.zip: %s", dir, resp.Status)
	}
	f, err := os.CreateTemp(tmpDir, "osv-"+strings.ToLower(dir)+"-*.zip")
	if err != nil {
		return "", "", 0, err
	}
	defer func() {
		f.Close()
		if err != nil {
			os.Remove(f.Name())
		}
	}()
	h := md5.New()
	body := &progressReader{r: resp.Body, onRead: func() { watchdog.Reset(StallTimeout) }}
	size, err = io.Copy(io.MultiWriter(f, h), body)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil && cause != context.Canceled {
			err = cause
		}
		return "", "", 0, fmt.Errorf("download %s/all.zip: %w", dir, err)
	}
	if resp.ContentLength >= 0 && size != resp.ContentLength {
		return "", "", 0, fmt.Errorf("download %s/all.zip: got %d of %d bytes", dir, size, resp.ContentLength)
	}
	if want := googMD5(resp.Header); want != "" && want != base64.StdEncoding.EncodeToString(h.Sum(nil)) {
		return "", "", 0, fmt.Errorf("download %s/all.zip: md5 mismatch", dir)
	}
	if err = f.Close(); err != nil {
		return "", "", 0, err
	}
	return f.Name(), resp.Header.Get("ETag"), size, nil
}

type progressReader struct {
	r      io.Reader
	onRead func()
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.onRead()
	}
	return n, err
}

func googMD5(h http.Header) string {
	for _, v := range h.Values("X-Goog-Hash") {
		for _, part := range strings.Split(v, ",") {
			if m, ok := strings.CutPrefix(strings.TrimSpace(part), "md5="); ok {
				return m
			}
		}
	}
	return ""
}

// ModifiedEntry is one line of modified_id.csv.
type ModifiedEntry struct {
	Modified time.Time
	ID       string
}

// ModifiedSince reads <dir>/modified_id.csv (newest first) and returns
// the entries strictly newer than since, stopping at the first older one
// so only the head of the file is parsed. notModified is true (and
// nothing else is returned) when etag still matches.
func (c *Client) ModifiedSince(ctx context.Context, dir string, since time.Time, etag string) (entries []ModifiedEntry, newETag string, notModified bool, err error) {
	resp, err := c.get(ctx, c.url(dir, "modified_id.csv"), etag)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", false, fmt.Errorf("GET %s/modified_id.csv: %s", dir, resp.Status)
	}
	entries, err = ParseModifiedCSV(resp.Body, since)
	return entries, resp.Header.Get("ETag"), false, err
}

// ParseModifiedCSV parses modified_id.csv content up to the first entry
// not newer than since.
func ParseModifiedCSV(r io.Reader, since time.Time) ([]ModifiedEntry, error) {
	var out []ModifiedEntry
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		ts, id, ok := strings.Cut(line, ",")
		if !ok {
			return nil, fmt.Errorf("modified_id.csv: bad line %q", line)
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, fmt.Errorf("modified_id.csv: bad time in %q: %w", line, err)
		}
		if !t.After(since) {
			break // sorted newest first
		}
		out = append(out, ModifiedEntry{Modified: t.UTC(), ID: id})
	}
	return out, sc.Err()
}

// Get fetches and returns <dir>/<id>.json.
func (c *Client) Get(ctx context.Context, dir, id string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	resp, err := c.get(ctx, c.url(dir, id+".json"), "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("GET %s/%s.json: %s", dir, id, resp.Status)
	}
}
