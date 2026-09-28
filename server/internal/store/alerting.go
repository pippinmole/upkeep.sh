package store

// Alerting storage (migration 0009): the alert_events outbox written by
// transitions, rule evaluation, digests, and the delivery log. The rule
// logic itself is in internal/alerting; channel types in internal/notify.

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

// alertingLock serializes evaluation and digest flushing (dedup state and
// digest items are read-modify-write). pg_advisory_xact_lock key.
const alertingLock = 0x75706b_616c7274 // "upk" "alrt"

// ErrNotFound: the row is gone.
var ErrNotFound = errors.New("not found")

// hasRuleForSQL is true when the user aliased by userCol has an enabled
// rule selecting the event type in typeCol: events nobody listens for are
// never written.
func hasRuleForSQL(userCol, typeCol string) string {
	return fmt.Sprintf(`EXISTS (SELECT 1 FROM alert_rules r WHERE r.user_id = %s AND r.enabled AND %s = ANY (r.event_types))`, userCol, typeCol)
}

// insertFindingEvents writes finding.* events for the given transitions of
// one host's findings, inside the reconcile transaction (the findings rows
// are already written, so the payload is their new state). Archived hosts
// (migration 0011, merged ones included) never alert.
func insertFindingEvents(ctx context.Context, tx pgx.Tx, hostID string, keys, types []string, now time.Time) (int, error) {
	if len(keys) == 0 {
		return 0, nil
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO alert_events (user_id, type, subject, occurred_at, host_ids, severity_rank, is_kev, payload)
		SELECT h.user_id, t.type, 'finding:' || f.host_id || ':' || f.dedup_key, $4, ARRAY[f.host_id],
		       f.severity_rank, f.is_kev,
		       jsonb_build_object(
		         'host', jsonb_build_object('id', h.id, 'hostname', h.hostname, 'label', h.label),
		         'finding', jsonb_build_object(
		           'id', f.id, 'kind', f.kind, 'vuln_key', f.vuln_key, 'source_package', f.source_package,
		           'packages', to_jsonb(f.packages), 'installed_version', f.installed_version,
		           'fixed_version', f.fixed_version, 'fix_channel', f.fix_channel,
		           'severity', f.severity, 'severity_rank', f.severity_rank, 'kev', f.is_kev,
		           'epss', f.epss_score, 'status', f.status, 'first_seen_at', f.first_seen_at)
		           || CASE WHEN f.image_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object(
		                'image_id', f.image_id, 'image_refs', to_jsonb(f.image_refs),
		                'containers', to_jsonb(f.container_names)) END)
		FROM unnest($2::text[], $3::text[]) AS t(dedup_key, type)
		JOIN findings f ON f.host_id = $1 AND f.dedup_key = t.dedup_key
		JOIN hosts h ON h.id = f.host_id
		WHERE h.archived_at IS NULL AND `+hasRuleForSQL("h.user_id", "t.type"), hostID, keys, types, now)
	if err != nil {
		return 0, fmt.Errorf("insert finding alert events: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// AgentHealthResult reports one agent health pass.
type AgentHealthResult struct {
	Changed, Events int
}

// CheckAgentHealth compares every active (not revoked, ever seen) agent's
// staleness with the state last recorded in agent_health and, on a change,
// writes agent.stale / agent.recovered events. Stale uses the dashboard's
// rule: silent for more than greatest(3*coalesce(push_interval_seconds,
// 900), 120) seconds. First observations are recorded silently. Archived
// hosts are left out of the events' host_ids and payload, so a
// host-scoped rule doesn't match on them.
func (s *Store) CheckAgentHealth(ctx context.Context, now time.Time) (AgentHealthResult, error) {
	var res AgentHealthResult
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(alertingLock)+1); err != nil {
		return res, err
	}
	staleSQL := staleAgentSQL("$1::timestamptz")
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE agent_health_cur ON COMMIT DROP AS
		SELECT a.id, a.user_id, a.name, a.last_seen_at,
		       CASE WHEN `+staleSQL+` THEN 'stale' ELSE 'online' END AS state
		FROM agents a WHERE a.revoked_at IS NULL AND a.last_seen_at IS NOT NULL
	`, now); err != nil {
		return res, err
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM agent_health ah WHERE NOT EXISTS (SELECT 1 FROM agent_health_cur c WHERE c.id = ah.agent_id)
	`); err != nil {
		return res, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_health (agent_id, state, changed_at)
		SELECT id, state, $1 FROM agent_health_cur ON CONFLICT (agent_id) DO NOTHING
	`, now); err != nil {
		return res, err
	}
	rows, err := tx.Query(ctx, `
		UPDATE agent_health ah SET state = c.state, changed_at = $1
		FROM agent_health_cur c WHERE c.id = ah.agent_id AND ah.state <> c.state
		RETURNING c.id
	`, now)
	if err != nil {
		return res, err
	}
	changed, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	res.Changed = len(changed)
	if len(changed) > 0 {
		tag, err := tx.Exec(ctx, `
			INSERT INTO alert_events (user_id, type, subject, occurred_at, host_ids, payload)
			SELECT c.user_id, e.type, 'agent:' || c.id, $2,
			       COALESCE((SELECT array_agg(ah.host_id ORDER BY ah.host_id)
			                 FROM agent_hosts ah JOIN hosts h ON h.id = ah.host_id
			                 WHERE ah.agent_id = c.id AND h.archived_at IS NULL), '{}'),
			       jsonb_build_object('agent', jsonb_build_object(
			         'id', c.id, 'name', c.name, 'last_seen_at', c.last_seen_at,
			         'hosts', COALESCE((SELECT jsonb_agg(jsonb_build_object('id', h.id, 'hostname', h.hostname, 'label', h.label) ORDER BY h.hostname)
			                            FROM agent_hosts ah JOIN hosts h ON h.id = ah.host_id
			                            WHERE ah.agent_id = c.id AND h.archived_at IS NULL), '[]')))
			FROM agent_health_cur c
			CROSS JOIN LATERAL (SELECT CASE c.state WHEN 'stale' THEN 'agent.stale' ELSE 'agent.recovered' END AS type) e
			WHERE c.id = ANY ($1::uuid[]) AND `+hasRuleForSQL("c.user_id", "e.type"), changed, now)
		if err != nil {
			return res, fmt.Errorf("insert agent alert events: %w", err)
		}
		res.Events = int(tag.RowsAffected())
	}
	return res, tx.Commit(ctx)
}

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
	Events, Matched, Suppressed, Digested, Notifications, Deliveries int
}

type ruleWithChannels struct {
	alerting.Rule
	channels []channelRef
}

type channelRef struct{ id, name, typ string }

// loadRules loads the enabled rules of the given users with their enabled
// channels. Rules without an enabled channel are left out: nothing could
// be sent, so they neither dedup nor collect digest items.
func loadRules(ctx context.Context, tx pgx.Tx, userIDs []string, ruleIDs []string) (map[string][]*ruleWithChannels, error) {
	rows, err := tx.Query(ctx, `
		SELECT r.id::text, r.user_id::text, r.name, r.event_types, r.min_severity_rank, r.kev_only,
		       r.finding_kinds, r.host_ids::text[], r.dedup_window_seconds, r.digest, r.digest_interval_seconds,
		       r.last_digest_at, r.created_at,
		       array_agg(c.id::text ORDER BY c.name), array_agg(c.name ORDER BY c.name), array_agg(c.type ORDER BY c.name)
		FROM alert_rules r
		JOIN alert_rule_channels rc ON rc.rule_id = r.id
		JOIN notification_channels c ON c.id = rc.channel_id AND c.enabled
		WHERE r.enabled AND (r.user_id = ANY ($1::uuid[]) OR r.id = ANY ($2::uuid[]))
		GROUP BY r.id
		ORDER BY r.created_at, r.id
	`, userIDs, ruleIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]*ruleWithChannels{}
	for rows.Next() {
		var (
			r                  ruleWithChannels
			dedup, interval    int
			cids, cnames, ctyp []string
		)
		if err := rows.Scan(&r.ID, &r.UserID, &r.Name, &r.EventTypes, &r.MinSeverityRank, &r.KEVOnly,
			&r.FindingKinds, &r.HostIDs, &dedup, &r.Digest, &interval, &r.LastDigestAt, &r.CreatedAt, &cids, &cnames, &ctyp); err != nil {
			return nil, err
		}
		r.DedupWindow = time.Duration(dedup) * time.Second
		r.DigestInterval = time.Duration(interval) * time.Second
		for i := range cids {
			r.channels = append(r.channels, channelRef{cids[i], cnames[i], ctyp[i]})
		}
		out[r.UserID] = append(out[r.UserID], &r)
	}
	return out, rows.Err()
}

type eventRow struct {
	meta    alerting.EventMeta
	payload []byte
	at      time.Time
}

func (e eventRow) event(dashboardURL string) (notify.Event, error) {
	var ev notify.Event
	if err := json.Unmarshal(e.payload, &ev); err != nil {
		return ev, fmt.Errorf("event %d payload: %w", e.meta.ID, err)
	}
	ev.ID, ev.Type, ev.OccurredAt = e.meta.ID, e.meta.Type, e.at.UTC()
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
	case ev.Agent != nil:
		return base + "/dashboard/agents"
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

// EvaluateAlerts drains the alert_events outbox: every pending event is
// matched against its user's enabled rules; matches that aren't dedup-
// suppressed become an immediate notification (batched per rule per pass)
// or a digest item. Events are marked processed in the same transaction.
func (s *Store) EvaluateAlerts(ctx context.Context, now time.Time, opt AlertOptions) (EvalResult, error) {
	var total EvalResult
	for {
		res, n, err := s.evaluateBatch(ctx, now, opt, 500)
		total.Events += res.Events
		total.Matched += res.Matched
		total.Suppressed += res.Suppressed
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
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(alertingLock)); err != nil {
		return res, 0, err
	}
	rows, err := tx.Query(ctx, `
		SELECT id, user_id::text, type, subject, host_ids::text[], severity_rank, is_kev,
		       coalesce(payload->'finding'->>'kind', ''), payload, occurred_at
		FROM alert_events WHERE processed_at IS NULL ORDER BY id LIMIT $1
	`, limit)
	if err != nil {
		return res, 0, err
	}
	var events []eventRow
	users := map[string]bool{}
	for rows.Next() {
		var e eventRow
		if err := rows.Scan(&e.meta.ID, &e.meta.UserID, &e.meta.Type, &e.meta.Subject, &e.meta.HostIDs,
			&e.meta.SeverityRank, &e.meta.KEV, &e.meta.FindingKind, &e.payload, &e.at); err != nil {
			rows.Close()
			return res, 0, err
		}
		events = append(events, e)
		users[e.meta.UserID] = true
	}
	if err := rows.Err(); err != nil {
		return res, 0, err
	}
	res.Events = len(events)
	if len(events) == 0 {
		return res, 0, nil
	}
	userIDs := make([]string, 0, len(users))
	for u := range users {
		userIDs = append(userIDs, u)
	}
	rules, err := loadRules(ctx, tx, userIDs, nil)
	if err != nil {
		return res, 0, err
	}

	// Candidate (rule, event) matches, then dedup against stored state.
	type match struct {
		rule *ruleWithChannels
		ev   eventRow
		key  string
	}
	var matches []match
	var mRules, mKeys []string
	for _, e := range events {
		for _, r := range rules[e.meta.UserID] {
			if alerting.Match(r.Rule, e.meta) {
				k := alerting.DedupKey(e.meta)
				matches = append(matches, match{r, e, k})
				mRules, mKeys = append(mRules, r.ID), append(mKeys, k)
			}
		}
	}
	res.Matched = len(matches)
	lastSent := map[[2]string]time.Time{}
	if len(matches) > 0 {
		rows, err := tx.Query(ctx, `
			SELECT d.rule_id::text, d.dedup_key, d.last_sent_at
			FROM alert_dedup d JOIN unnest($1::uuid[], $2::text[]) AS m(rule_id, key)
			  ON d.rule_id = m.rule_id AND d.dedup_key = m.key
		`, mRules, mKeys)
		if err != nil {
			return res, 0, err
		}
		for rows.Next() {
			var r, k string
			var t time.Time
			if err := rows.Scan(&r, &k, &t); err != nil {
				rows.Close()
				return res, 0, err
			}
			lastSent[[2]string{r, k}] = t
		}
		if err := rows.Err(); err != nil {
			return res, 0, err
		}
	}

	var sentRules, sentKeys []string
	var digestRules []string
	var digestEvents []int64
	immediate := map[string][]eventRow{}
	var order []*ruleWithChannels
	for _, m := range matches {
		dk := [2]string{m.rule.ID, m.key}
		var last *time.Time
		if t, ok := lastSent[dk]; ok {
			last = &t
		}
		if alerting.Suppressed(last, m.rule.DedupWindow, now) {
			res.Suppressed++
			continue
		}
		// Recording now also dedups repeats within this batch. Without a
		// window nothing is recorded (and a key may repeat in the batch).
		if m.rule.DedupWindow > 0 {
			lastSent[dk] = now
			sentRules, sentKeys = append(sentRules, m.rule.ID), append(sentKeys, m.key)
		}
		if m.rule.Digest {
			digestRules, digestEvents = append(digestRules, m.rule.ID), append(digestEvents, m.ev.meta.ID)
			res.Digested++
			continue
		}
		if _, seen := immediate[m.rule.ID]; !seen {
			order = append(order, m.rule)
		}
		immediate[m.rule.ID] = append(immediate[m.rule.ID], m.ev)
	}

	if len(sentRules) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO alert_dedup (rule_id, dedup_key, last_sent_at)
			SELECT rule_id, key, $3 FROM unnest($1::uuid[], $2::text[]) AS m(rule_id, key)
			ON CONFLICT (rule_id, dedup_key) DO UPDATE SET last_sent_at = EXCLUDED.last_sent_at
		`, sentRules, sentKeys, now); err != nil {
			return res, 0, err
		}
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
		ids[i] = e.meta.ID
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
			INSERT INTO notifications (id, user_id, rule_id, kind, event_count, summary, payload, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, n.ID, r.UserID, r.ID, kind, len(chunk), n.Summary, payload, now); err != nil {
			return nil, 0, err
		}
		for _, c := range r.channels {
			var id string
			if err := tx.QueryRow(ctx, `
				INSERT INTO notification_deliveries (user_id, notification_id, channel_id, channel_name, channel_type, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING id::text
			`, r.UserID, n.ID, c.id, c.name, c.typ, now).Scan(&id); err != nil {
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
	defer tx.Rollback(ctx)
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
	rules, err := loadRules(ctx, tx, nil, ruleIDs)
	if err != nil {
		return res, err
	}
	live := map[string]*ruleWithChannels{}
	for _, rs := range rules {
		for _, r := range rs {
			live[r.ID] = r
		}
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
			RETURNING e.id, e.user_id::text, e.type, e.subject, e.host_ids::text[], e.severity_rank, e.is_kev, e.payload, e.occurred_at
		`, id)
		if err != nil {
			return res, err
		}
		evs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (eventRow, error) {
			var e eventRow
			err := row.Scan(&e.meta.ID, &e.meta.UserID, &e.meta.Type, &e.meta.Subject, &e.meta.HostIDs,
				&e.meta.SeverityRank, &e.meta.KEV, &e.payload, &e.at)
			return e, err
		})
		if err != nil {
			return res, err
		}
		if len(evs) == 0 {
			continue
		}
		slices.SortFunc(evs, func(a, b eventRow) int { return cmp.Compare(a.meta.ID, b.meta.ID) })
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
	ID, UserID, Status, Kind string
	ChannelID                *string
	ChannelType              string
	ChannelEnabled           bool
	Config                   notify.Config
	Notification             notify.Notification
	NotificationID           string
	HasPayload               bool
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
		SELECT d.id::text, d.user_id::text, d.status, n.kind, n.id::text, d.channel_id::text,
		       COALESCE(c.type, d.channel_type), c.enabled, c.config, c.secrets, n.payload, n.created_at,
		       r.id::text, r.snapshot
		FROM notification_deliveries d
		JOIN notifications n ON n.id = d.notification_id
		LEFT JOIN notification_channels c ON c.id = d.channel_id
		LEFT JOIN reports r ON r.id = n.report_id
		WHERE d.id = $1
	`, id).Scan(&d.ID, &d.UserID, &d.Status, &d.Kind, &d.NotificationID, &d.ChannelID, &d.ChannelType,
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
	defer tx.Rollback(ctx)
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
	Events, Notifications, Dedup, Reports int64
}

// PruneAlerting deletes processed events older than eventAge (unless a
// digest still holds them), notifications (with their deliveries and
// attempts) older than logAge, dedup marks older than the longest
// possible window, and reports older than reportAge except each
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
	if tag, err = s.Pool.Exec(ctx, `DELETE FROM alert_dedup WHERE last_sent_at < $1`, now.Add(-8*24*time.Hour)); err != nil {
		return res, err
	}
	res.Dedup = tag.RowsAffected()
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
	res.Dedup = tag.RowsAffected()
	return res, nil
}
