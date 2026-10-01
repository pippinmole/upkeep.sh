package store

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/cvefeeds"
)

// ApplyKEV makes cves' KEV columns match the catalog exactly: listed CVEs
// are flagged (rows created as needed), CVEs no longer listed are
// unflagged. One transaction.
func (s *Store) ApplyKEV(ctx context.Context, cat cvefeeds.KEVCatalog) (flagged, unflagged int, err error) {
	n := len(cat.Entries)
	ids := make([]string, n)
	added := make([]time.Time, n)
	due := make([]*time.Time, n)
	ransom := make([]bool, n)
	for i, e := range cat.Entries {
		ids[i], added[i], due[i], ransom[i] = e.CVE, e.DateAdded, e.DueDate, e.Ransomware
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		INSERT INTO cves (id, is_kev, kev_added_at, kev_due_date, kev_ransomware)
		SELECT id, true, added, due, ransom
		FROM unnest($1::text[], $2::date[], $3::date[], $4::bool[]) AS t(id, added, due, ransom)
		ON CONFLICT (id) DO UPDATE SET
			is_kev = true, kev_added_at = EXCLUDED.kev_added_at,
			kev_due_date = EXCLUDED.kev_due_date, kev_ransomware = EXCLUDED.kev_ransomware,
			updated_at = now()
		WHERE (cves.is_kev, cves.kev_added_at, cves.kev_due_date, cves.kev_ransomware)
		      IS DISTINCT FROM (true, EXCLUDED.kev_added_at, EXCLUDED.kev_due_date, EXCLUDED.kev_ransomware)
	`, ids, added, due, ransom)
	if err != nil {
		return 0, 0, err
	}
	flagged = int(tag.RowsAffected())
	tag, err = tx.Exec(ctx, `
		UPDATE cves SET is_kev = false, kev_added_at = NULL, kev_due_date = NULL,
		                kev_ransomware = NULL, updated_at = now()
		WHERE is_kev AND id NOT IN (SELECT unnest($1::text[]))
	`, ids)
	if err != nil {
		return 0, 0, err
	}
	return flagged, int(tag.RowsAffected()), tx.Commit(ctx)
}

// ApplyEPSS bulk-loads an EPSS feed: rows are streamed into a temp table
// with COPY, then merged into cves in one statement. Only rows whose score
// or percentile changed are updated, so epss_date is the score date of the
// feed that last changed that CVE's values.
func (s *Store) ApplyEPSS(ctx context.Context, r *cvefeeds.EPSSReader) (rows, updated int, err error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE epss_stage (id text, score text, pct text) ON COMMIT DROP
	`); err != nil {
		return 0, 0, err
	}
	src := &epssSource{r: r}
	n, err := tx.CopyFrom(ctx, pgx.Identifier{"epss_stage"}, []string{"id", "score", "pct"}, src)
	if err != nil {
		return 0, 0, err
	}
	if n == 0 {
		return 0, 0, errors.New("epss: feed has no rows")
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO cves (id, epss_score, epss_percentile, epss_date)
		SELECT DISTINCT ON (id) id, score::numeric, pct::numeric, $1::date FROM epss_stage
		ORDER BY id
		ON CONFLICT (id) DO UPDATE SET
			epss_score = EXCLUDED.epss_score, epss_percentile = EXCLUDED.epss_percentile,
			epss_date = EXCLUDED.epss_date, updated_at = now()
		WHERE (cves.epss_score, cves.epss_percentile)
		      IS DISTINCT FROM (EXCLUDED.epss_score, EXCLUDED.epss_percentile)
	`, r.Header.ScoreDate)
	if err != nil {
		return 0, 0, err
	}
	return int(n), int(tag.RowsAffected()), tx.Commit(ctx)
}

// epssSource adapts EPSSReader to pgx.CopyFromSource.
type epssSource struct {
	r   *cvefeeds.EPSSReader
	cur cvefeeds.EPSSScore
	err error
}

func (e *epssSource) Next() bool {
	e.cur, e.err = e.r.Next()
	if errors.Is(e.err, io.EOF) {
		e.err = nil
		return false
	}
	return e.err == nil
}

func (e *epssSource) Values() ([]any, error) {
	return []any{e.cur.CVE, e.cur.Score, e.cur.Percentile}, nil
}

func (e *epssSource) Err() error { return e.err }

// FeedState is a feed_sync_state row.
type FeedState struct {
	Feed           string
	LastSuccessAt  *time.Time
	LastFullSyncAt *time.Time
	Cursor         string
	ETag           string
	ConfigHash     string
}

// GetFeedState returns the feed's state, or a zero state (Feed set) if the
// feed has never run.
func (s *Store) GetFeedState(ctx context.Context, feed string) (FeedState, error) {
	st := FeedState{Feed: feed}
	var cursor, etag, cfg *string
	err := s.Pool.QueryRow(ctx, `
		SELECT last_success_at, last_full_sync_at, cursor, etag, config_hash
		FROM feed_sync_state WHERE feed = $1
	`, feed).Scan(&st.LastSuccessAt, &st.LastFullSyncAt, &cursor, &etag, &cfg)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	st.Cursor, st.ETag, st.ConfigHash = deref(cursor), deref(etag), deref(cfg)
	return st, nil
}

// FeedAttempt records that a sync of feed started.
func (s *Store) FeedAttempt(ctx context.Context, feed string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO feed_sync_state (feed, last_attempt_at) VALUES ($1, now())
		ON CONFLICT (feed) DO UPDATE SET last_attempt_at = now()
	`, feed)
	return err
}

// FeedSuccess is what a successful sync records. Empty strings leave the
// stored cursor/etag/config_hash unchanged.
type FeedSuccess struct {
	Cursor, ETag, ConfigHash string
	Full                     bool // sets last_full_sync_at
	Stats                    any
}

func (s *Store) FeedSucceeded(ctx context.Context, feed string, u FeedSuccess) error {
	stats, err := json.Marshal(u.Stats)
	if err != nil || u.Stats == nil {
		stats = []byte("{}")
	}
	_, err = s.Pool.Exec(ctx, `
		INSERT INTO feed_sync_state (feed, last_attempt_at, last_success_at, last_full_sync_at,
		                             cursor, etag, config_hash, last_error, stats)
		VALUES ($1, now(), now(), CASE WHEN $2 THEN now() END, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''), NULL, $6)
		ON CONFLICT (feed) DO UPDATE SET
			last_success_at   = now(),
			last_full_sync_at = CASE WHEN $2 THEN now() ELSE feed_sync_state.last_full_sync_at END,
			cursor            = COALESCE(NULLIF($3, ''), feed_sync_state.cursor),
			etag              = COALESCE(NULLIF($4, ''), feed_sync_state.etag),
			config_hash       = COALESCE(NULLIF($5, ''), feed_sync_state.config_hash),
			last_error        = NULL,
			stats             = $6
	`, feed, u.Full, u.Cursor, u.ETag, u.ConfigHash, stats)
	return err
}

func (s *Store) FeedFailed(ctx context.Context, feed string, syncErr error) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO feed_sync_state (feed, last_attempt_at, last_error) VALUES ($1, now(), $2)
		ON CONFLICT (feed) DO UPDATE SET last_error = EXCLUDED.last_error
	`, feed, syncErr.Error())
	return err
}
