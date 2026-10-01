package store

// Alerting storage (migrations 0009, 0024): the alert_events outbox of
// alert instance transitions (written by EvaluateAlertRules,
// alertrules.go), notification dispatch, digests, and the delivery log.
// The rule logic itself is in internal/alerting; channel types in
// internal/notify.

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/alerting"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/reports"
)

// alertingLock serializes dispatch and digest flushing (digest items are
// read-modify-write). pg_advisory_xact_lock key.
const alertingLock = 0x75706b_616c7274 // "upk" "alrt"

// ErrNotFound: the row is gone.
var ErrNotFound = errors.New("not found")

// EnqueueDeliveries is called inside the transaction that created
// deliveries (River InsertTx), so a delivery job exists iff its row does.
type EnqueueDeliveries func(ctx context.Context, tx pgx.Tx, deliveryIDs []string) error

// AlertOptions configures evaluation and digests.
type AlertOptions struct {
	// DashboardURL, when set, adds a dashboard link to each event.
	DashboardURL string
	Enqueue      EnqueueDeliveries
}

// EvalResult reports an evaluation pass.
type EvalResult struct {
	Events, Sent, Skipped, Digested, Notifications, Deliveries int
}

type ruleWithChannels struct {
	alerting.Rule
	channels []channelRef
}

type channelRef struct{ id, name, typ string }

// loadRules loads the given enabled rules with their enabled channels.
// Rules without an enabled channel are left out: nothing could be sent,
// so they collect no digest items either.
func loadRules(ctx context.Context, tx pgx.Tx, ruleIDs []string) (map[string]*ruleWithChannels, error) {
	rows, err := tx.Query(ctx, `
		SELECT r.id::text, r.workspace_id::text, r.name, r.notify_on_resolve, r.digest, r.digest_interval_seconds,
		       r.last_digest_at, r.created_at,
		       array_agg(c.id::text ORDER BY c.name), array_agg(c.name ORDER BY c.name), array_agg(c.type ORDER BY c.name)
		FROM alert_rules r
		JOIN alert_rule_channels rc ON rc.rule_id = r.id
		JOIN notification_channels c ON c.id = rc.channel_id AND c.enabled
		WHERE r.enabled AND r.id = ANY ($1::uuid[])
		GROUP BY r.id
	`, ruleIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*ruleWithChannels{}
	for rows.Next() {
		var (
			r                  ruleWithChannels
			interval           int
			cids, cnames, ctyp []string
		)
		if err := rows.Scan(&r.ID, &r.WorkspaceID, &r.Name, &r.NotifyOnResolve, &r.Digest, &interval,
			&r.LastDigestAt, &r.CreatedAt, &cids, &cnames, &ctyp); err != nil {
			return nil, err
		}
		r.DigestInterval = time.Duration(interval) * time.Second
		for i := range cids {
			r.channels = append(r.channels, channelRef{cids[i], cnames[i], ctyp[i]})
		}
		out[r.ID] = &r
	}
	return out, rows.Err()
}

type eventRow struct {
	id      int64
	ruleID  string
	typ     string
	payload []byte
	at      time.Time
}

func (e eventRow) event(dashboardURL string) (notify.Event, error) {
	var ev notify.Event
	if err := json.Unmarshal(e.payload, &ev); err != nil {
		return ev, fmt.Errorf("event %d payload: %w", e.id, err)
	}
	ev.ID, ev.Type, ev.OccurredAt = e.id, e.typ, e.at.UTC()
	ev.URL = eventURL(dashboardURL, ev)
	return ev, nil
}

func eventURL(base string, ev notify.Event) string {
	base = strings.TrimRight(base, "/")
	if base == "" {
		return ""
	}
	switch {
	case ev.Finding != nil && ev.Host != nil && ev.Finding.ImageID != "":
		// The image detail page's Vulnerabilities tab, searched to this
		// vulnerability; ?host= picks the platform the image has on that
		// host (web/src/lib/image-key.ts).
		return ImageFindingURL(base, ev.Finding.ImageID, ev.Host.ID, ev.Finding.VulnKey)
	case ev.Finding != nil && ev.Host != nil:
		return base + "/dashboard/hosts/" + url.PathEscape(ev.Host.ID) + "/vulnerabilities?v=" + url.QueryEscape(ev.Finding.VulnKey)
	case ev.Host != nil:
		// The alerts list filtered to the host (web/src/lib/alerts-table.ts).
		return base + "/dashboard/alerts?host=" + url.QueryEscape(ev.Host.ID)
	}
	return ""
}

// ImageFindingURL is the dashboard link for an image finding: the image
// detail page (/dashboard/images/-/<image id>, see
// web/src/lib/image-key.ts) on its Vulnerabilities tab, filtered to the
// vulnerability, with the host choosing the platform.
func ImageFindingURL(base, imageID, hostID, vulnKey string) string {
	q := url.Values{}
	q.Set("host", hostID)
	q.Set("tab", "vulnerabilities")
	q.Set("q", vulnKey)
	return strings.TrimRight(base, "/") + "/dashboard/images/-/" + url.PathEscape(imageID) + "?" + q.Encode()
}

// EvaluateAlerts drains the alert_events outbox: every pending event
// (an alert instance transition, written by EvaluateAlertRules) is sent
// through its rule, if the rule is still enabled, has an enabled channel
// and sends that type: as an immediate notification (batched per rule per
// pass) or a digest item. Events are marked processed in the same
// transaction. Dedup is the instance state machine: an event exists only
// for a transition.
func (s *Store) EvaluateAlerts(ctx context.Context, now time.Time, opt AlertOptions) (EvalResult, error) {
	var total EvalResult
	for {
		res, n, err := s.evaluateBatch(ctx, now, opt, 500)
		total.Events += res.Events
		total.Sent += res.Sent
		total.Skipped += res.Skipped
		total.Digested += res.Digested
		total.Notifications += res.Notifications
		total.Deliveries += res.Deliveries
		if err != nil || n < 500 {
			return total, err
		}
	}
}

func (s *Store) evaluateBatch(ctx context.Context, now time.Time, opt AlertOptions, limit int) (EvalResult, int, error) {
	var res EvalResult
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(alertingLock)); err != nil {
		return res, 0, err
	}
	rows, err := tx.Query(ctx, `
		SELECT id, rule_id::text, type, payload, occurred_at
		FROM alert_events WHERE processed_at IS NULL ORDER BY id LIMIT $1
	`, limit)
	if err != nil {
		return res, 0, err
	}
	events, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (eventRow, error) {
		var e eventRow
		err := r.Scan(&e.id, &e.ruleID, &e.typ, &e.payload, &e.at)
		return e, err
	})
	if err != nil {
		return res, 0, err
	}
	res.Events = len(events)
	if len(events) == 0 {
		return res, 0, nil
	}
	ruleIDs := make([]string, 0, len(events))
	for _, e := range events {
		if !slices.Contains(ruleIDs, e.ruleID) {
			ruleIDs = append(ruleIDs, e.ruleID)
		}
	}
	rules, err := loadRules(ctx, tx, ruleIDs)
	if err != nil {
		return res, 0, err
	}

	var digestRules []string
	var digestEvents []int64
	immediate := map[string][]eventRow{}
	var order []*ruleWithChannels
	for _, e := range events {
		r := rules[e.ruleID]
		if r == nil || !r.Sends(e.typ) {
			res.Skipped++ // disabled, no channel left, or resolutions off since
			continue
		}
		res.Sent++
		if r.Digest {
			digestRules, digestEvents = append(digestRules, r.ID), append(digestEvents, e.id)
			res.Digested++
			continue
		}
		if _, seen := immediate[r.ID]; !seen {
			order = append(order, r)
		}
		immediate[r.ID] = append(immediate[r.ID], e)
	}

	if len(digestRules) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO alert_digest_items (rule_id, event_id)
			SELECT * FROM unnest($1::uuid[], $2::bigint[]) ON CONFLICT DO NOTHING
		`, digestRules, digestEvents); err != nil {
			return res, 0, err
		}
	}
	var deliveries []string
	for _, r := range order {
		ids, nNotif, err := createNotifications(ctx, tx, r, notify.KindAlert, immediate[r.ID], now, opt.DashboardURL)
		if err != nil {
			return res, 0, err
		}
		res.Notifications += nNotif
		deliveries = append(deliveries, ids...)
	}
	res.Deliveries = len(deliveries)

	ids := make([]int64, len(events))
	for i, e := range events {
		ids[i] = e.id
	}
	if _, err := tx.Exec(ctx, `UPDATE alert_events SET processed_at = $2 WHERE id = ANY ($1)`, ids, now); err != nil {
		return res, 0, err
	}
	if len(deliveries) > 0 && opt.Enqueue != nil {
		if err := opt.Enqueue(ctx, tx, deliveries); err != nil {
			return res, 0, err
		}
	}
	return res, len(events), tx.Commit(ctx)
}

// createNotifications writes the notification(s) for one rule's events
// (split into chunks of alerting.MaxEventsPerNotification) and a pending
// delivery per channel, returning the delivery ids.
func createNotifications(ctx context.Context, tx pgx.Tx, r *ruleWithChannels, kind string, rows []eventRow, now time.Time, dashboardURL string) ([]string, int, error) {
	events := make([]notify.Event, 0, len(rows))
	for _, e := range rows {
		ev, err := e.event(dashboardURL)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, ev)
	}
	var deliveries []string
	chunks := alerting.Chunk(events)
	for _, chunk := range chunks {
		n := notify.Notification{
			Version: notify.PayloadVersion, Kind: kind, CreatedAt: now,
			Rule:    &notify.RuleRef{ID: r.ID, Name: r.Name},
			Summary: alerting.Summary(kind, chunk), Events: chunk,
		}
		if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&n.ID); err != nil {
			return nil, 0, err
		}
		payload, err := json.Marshal(n)
		if err != nil {
			return nil, 0, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO notifications (id, workspace_id, rule_id, kind, event_count, summary, payload, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, n.ID, r.WorkspaceID, r.ID, kind, len(chunk), n.Summary, payload, now); err != nil {
			return nil, 0, err
		}
		for _, c := range r.channels {
			var id string
			if err := tx.QueryRow(ctx, `
				INSERT INTO notification_deliveries (workspace_id, notification_id, channel_id, channel_name, channel_type, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING id::text
			`, r.WorkspaceID, n.ID, c.id, c.name, c.typ, now).Scan(&id); err != nil {
				return nil, 0, err
			}
			deliveries = append(deliveries, id)
		}
	}
	return deliveries, len(chunks), nil
}

// DigestResult reports a digest flush.
type DigestResult struct {
	Rules, Events, Notifications, Deliveries int
}

// FlushDigests sends each rule's pending digest items as one notification
// once its digest interval has elapsed (alerting.DigestDue). Items of
// rules that were disabled or lost all channels are dropped; items of a
// rule switched to immediate are sent at once.
func (s *Store) FlushDigests(ctx context.Context, now time.Time, opt AlertOptions) (DigestResult, error) {
	var res DigestResult
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(alertingLock)); err != nil {
		return res, err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT rule_id::text FROM alert_digest_items`)
	if err != nil {
		return res, err
	}
	ruleIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(ruleIDs) == 0 {
		return res, err
	}
	live, err := loadRules(ctx, tx, ruleIDs)
	if err != nil {
		return res, err
	}
	var deliveries []string
	var drop []string
	for _, id := range ruleIDs {
		r := live[id]
		if r == nil {
			drop = append(drop, id)
			continue
		}
		if !alerting.DigestDue(r.Rule, now) {
			continue
		}
		rows, err := tx.Query(ctx, `
			DELETE FROM alert_digest_items i USING alert_events e
			WHERE i.rule_id = $1 AND e.id = i.event_id
			RETURNING e.id, e.rule_id::text, e.type, e.payload, e.occurred_at
		`, id)
		if err != nil {
			return res, err
		}
		evs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (eventRow, error) {
			var e eventRow
			err := row.Scan(&e.id, &e.ruleID, &e.typ, &e.payload, &e.at)
			return e, err
		})
		if err != nil {
			return res, err
		}
		if len(evs) == 0 {
			continue
		}
		slices.SortFunc(evs, func(a, b eventRow) int { return cmp.Compare(a.id, b.id) })
		kind := notify.KindDigest
		if !r.Digest {
			kind = notify.KindAlert
		}
		ids, n, err := createNotifications(ctx, tx, r, kind, evs, now, opt.DashboardURL)
		if err != nil {
			return res, err
		}
		if r.Digest {
			if _, err := tx.Exec(ctx, `UPDATE alert_rules SET last_digest_at = $2 WHERE id = $1`, id, now); err != nil {
				return res, err
			}
		}
		res.Rules++
		res.Events += len(evs)
		res.Notifications += n
		deliveries = append(deliveries, ids...)
	}
	if len(drop) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM alert_digest_items WHERE rule_id = ANY ($1::uuid[])`, drop); err != nil {
			return res, err
		}
	}
	res.Deliveries = len(deliveries)
	if len(deliveries) > 0 && opt.Enqueue != nil {
		if err := opt.Enqueue(ctx, tx, deliveries); err != nil {
			return res, err
		}
	}
	return res, tx.Commit(ctx)
}

// Delivery is everything alert_deliver needs for one delivery.
type Delivery struct {
	ID, WorkspaceID, Status, Kind string
	ChannelID                     *string
	ChannelType                   string
	ChannelEnabled                bool
	Config                        notify.Config
	Notification                  notify.Notification
	NotificationID                string
	HasPayload                    bool
	// ReportDeleted: a report notification whose report is gone (deleted
	// with its schedule; notifications.report_id is then NULL).
	ReportDeleted bool
}

// LoadDelivery loads a delivery with its channel config (secrets merged)
// and notification payload. For a report notification, Notification.Report
// carries the stored snapshot (its URL is left for the caller to set).
// ErrNotFound when the delivery is gone.
func (s *Store) LoadDelivery(ctx context.Context, id string) (Delivery, error) {
	var (
		d               Delivery
		config, secrets []byte
		payload         []byte
		enabled         *bool
		createdAt       time.Time
		reportID        *string
		snapshot        []byte
	)
	err := s.Pool.QueryRow(ctx, `
		SELECT d.id::text, d.workspace_id::text, d.status, n.kind, n.id::text, d.channel_id::text,
		       COALESCE(c.type, d.channel_type), c.enabled, c.config, c.secrets, n.payload, n.created_at,
		       r.id::text, r.snapshot
		FROM notification_deliveries d
		JOIN notifications n ON n.id = d.notification_id
		LEFT JOIN notification_channels c ON c.id = d.channel_id
		LEFT JOIN reports r ON r.id = n.report_id
		WHERE d.id = $1
	`, id).Scan(&d.ID, &d.WorkspaceID, &d.Status, &d.Kind, &d.NotificationID, &d.ChannelID, &d.ChannelType,
		&enabled, &config, &secrets, &payload, &createdAt, &reportID, &snapshot)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	if enabled == nil { // channel deleted
		d.ChannelID = nil
	} else {
		d.ChannelEnabled = *enabled
	}
	d.Config = notify.Config{}
	for _, raw := range [][]byte{config, secrets} {
		if len(raw) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return d, fmt.Errorf("channel config: %w", err)
		}
		for k, v := range m {
			switch v := v.(type) {
			case string:
				d.Config[k] = v
			case nil:
			default:
				d.Config[k] = fmt.Sprint(v)
			}
		}
	}
	if len(payload) > 0 {
		d.HasPayload = true
		if err := json.Unmarshal(payload, &d.Notification); err != nil {
			return d, fmt.Errorf("notification payload: %w", err)
		}
	} else {
		d.Notification = notify.Notification{
			Version: notify.PayloadVersion, ID: d.NotificationID, Kind: d.Kind, CreatedAt: createdAt.UTC(),
			Summary: alerting.Summary(d.Kind, nil), Events: []notify.Event{},
		}
	}
	if d.Kind == notify.KindReport {
		if reportID == nil {
			d.ReportDeleted = true
		} else {
			var snap reports.Snapshot
			if err := json.Unmarshal(snapshot, &snap); err != nil {
				return d, fmt.Errorf("report %s snapshot: %w", *reportID, err)
			}
			d.Notification.Report = &notify.Report{ID: *reportID, Snapshot: &snap}
		}
	}
	d.Notification.DeliveryID = d.ID
	return d, nil
}

// Delivery statuses.
const (
	DeliveryPending   = "pending"
	DeliveryRetrying  = "retrying"
	DeliveryDelivered = "delivered"
	DeliveryFailed    = "failed"
)

// Attempt is one delivery attempt's outcome.
type Attempt struct {
	StatusCode int // 0 = no response
	Error      string
	Duration   time.Duration
	Status     string // the delivery's status after this attempt
}

// RecordAttempt appends an attempt to the delivery log and updates the
// delivery's status. Returns the attempt number.
func (s *Store) RecordAttempt(ctx context.Context, deliveryID string, a Attempt, now time.Time) (int, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var code, errText any
	if a.StatusCode != 0 {
		code = a.StatusCode
	}
	if a.Error != "" {
		// Backstop only: notifiers already cap the response body they append.
		errText = truncate(a.Error, 64<<10)
	}
	var n int
	err = tx.QueryRow(ctx, `
		UPDATE notification_deliveries SET attempts = attempts + 1, status = $2, last_status_code = $3,
		       last_error = $4, updated_at = $5,
		       delivered_at = CASE WHEN $2 = 'delivered' THEN $5 ELSE delivered_at END
		WHERE id = $1 RETURNING attempts
	`, deliveryID, a.Status, code, errText, now).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO notification_delivery_attempts (delivery_id, attempt, attempted_at, status_code, error, duration_ms)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, deliveryID, n, now, code, errText, int(a.Duration.Milliseconds())); err != nil {
		return 0, err
	}
	return n, tx.Commit(ctx)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// PruneResult reports an alerting cleanup.
type PruneResult struct {
	Events, Notifications, Instances, Reports int64
}

// PruneAlerting deletes processed events older than eventAge (unless a
// digest still holds them), notifications (with their deliveries and
// attempts) and resolved alert instances older than logAge, and reports older than reportAge except each
// schedule's latest (the next run compares against it, and the dashboard
// keeps something to show for a schedule that stopped running). A pruned
// report's notifications.report_id and the next report's
// previous_report_id are set NULL by their foreign keys.
func (s *Store) PruneAlerting(ctx context.Context, now time.Time, eventAge, logAge, reportAge time.Duration) (PruneResult, error) {
	var res PruneResult
	tag, err := s.Pool.Exec(ctx, `
		DELETE FROM alert_events e WHERE e.processed_at < $1
		  AND NOT EXISTS (SELECT 1 FROM alert_digest_items i WHERE i.event_id = e.id)
	`, now.Add(-eventAge))
	if err != nil {
		return res, err
	}
	res.Events = tag.RowsAffected()
	if tag, err = s.Pool.Exec(ctx, `DELETE FROM notifications WHERE created_at < $1`, now.Add(-logAge)); err != nil {
		return res, err
	}
	res.Notifications = tag.RowsAffected()
	// Alert history: resolved instances, on the delivery log's retention.
	if tag, err = s.Pool.Exec(ctx, `DELETE FROM alert_instances WHERE state = 'resolved' AND resolved_at < $1`, now.Add(-logAge)); err != nil {
		return res, err
	}
	res.Instances = tag.RowsAffected()
	// "Latest" is LatestReport's order (generated_at, then id), so exactly
	// one report per schedule survives however old it is.
	if tag, err = s.Pool.Exec(ctx, `
		DELETE FROM reports r WHERE r.generated_at < $1
		  AND EXISTS (SELECT 1 FROM reports n WHERE n.schedule_id = r.schedule_id
		              AND (n.generated_at, n.id) > (r.generated_at, r.id)) -- reports_schedule_idx
	`, now.Add(-reportAge)); err != nil {
		return res, err
	}
	res.Reports = tag.RowsAffected()
	return res, nil
}
