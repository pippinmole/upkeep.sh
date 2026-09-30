package store

// Alert rule evaluation (docs/ALERTING.md "Evaluation"): each rule's
// condition is evaluated over its hosts (alertrules_eval.go), diffed
// against its firing alert_instances (alerting.Diff), and the transitions
// are written in one transaction together with the alert_events rows that
// notify (drained by EvaluateAlerts, store/alerting.go).
//
// Ownership: rules, instances and events belong to a workspace, like
// hosts; alertRuleHostsSQL is the one place a rule is joined to hosts.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/alerting"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
)

// alertRulesLock serializes rule evaluation (instances are
// read-modify-write). pg_advisory_xact_lock key.
const alertRulesLock = int64(alertingLock) + 2

// RuleEvalResult reports one evaluation pass.
type RuleEvalResult struct {
	Rules, Fired, Refreshed, Resolved, Events int
}

// AfterRuleEval runs inside the evaluation transaction (the worker uses it
// to InsertTx alert_evaluate when events were written).
type AfterRuleEval func(ctx context.Context, tx pgx.Tx, res RuleEvalResult) error

type ruleRow struct {
	id, workspaceID, name string
	enabled               bool
	condition             []byte
	hostIDs               []string // nil = all hosts
	notifyOnResolve       bool
	hasChannels           bool
	parsed                alerting.Condition
	parseErr              error
	hosts                 map[string]hostRef
	status                map[string]alerting.HostStatus
	evaluatedHostIDs      []string
	firing                []alerting.Firing
}

type hostRef struct {
	id, hostname string
	label        *string
}

// alertRuleHostsSQL lists a rule owner's hosts ($1 owner, $2 optional
// single host) with whether each is archived and in the rule's scope ($3
// host_ids, NULL = all).
const alertRuleHostsSQL = `
	SELECT h.id::text, h.hostname, h.label, h.archived_at IS NOT NULL,
	       ($3::uuid[] IS NULL OR h.id = ANY ($3::uuid[]))
	FROM hosts h
	WHERE h.workspace_id = $1 AND ($2::uuid IS NULL OR h.id = $2::uuid)`

// EvaluateAlertRules evaluates every rule of hostID's owner over that host,
// or, with hostID "", every rule over every host (the periodic pass, which
// also handles time-based properties, rule edits and deletions).
func (s *Store) EvaluateAlertRules(ctx context.Context, now time.Time, hostID string, after AfterRuleEval) (RuleEvalResult, error) {
	var res RuleEvalResult
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, alertRulesLock); err != nil {
		return res, err
	}
	var host, owner *string
	if hostID != "" {
		var u string
		err := tx.QueryRow(ctx, `SELECT workspace_id::text FROM hosts WHERE id = $1`, hostID).Scan(&u)
		if errors.Is(err, pgx.ErrNoRows) {
			return res, nil // deleted; its instances went with it
		}
		if err != nil {
			return res, err
		}
		host, owner = &hostID, &u
	}

	// Firing instances of deleted rules resolve silently.
	tag, err := tx.Exec(ctx, `
		UPDATE alert_instances SET state = 'resolved', resolved_at = $1, resolved_reason = 'rule_deleted'
		WHERE state = 'firing' AND rule_id IS NULL AND ($2::uuid IS NULL OR host_id = $2::uuid)
	`, now, host)
	if err != nil {
		return res, err
	}
	res.Resolved += int(tag.RowsAffected())

	rules, err := loadEvalRules(ctx, tx, owner)
	if err != nil {
		return res, err
	}
	for _, r := range rules {
		if err := evaluateRule(ctx, tx, r, host, now, &res); err != nil {
			return res, fmt.Errorf("rule %s: %w", r.id, err)
		}
	}
	if after != nil {
		if err := after(ctx, tx, res); err != nil {
			return res, err
		}
	}
	return res, tx.Commit(ctx)
}

// loadEvalRules: enabled rules, and disabled ones that still have firing
// instances to resolve; of one owner, or of everyone.
func loadEvalRules(ctx context.Context, tx pgx.Tx, owner *string) ([]*ruleRow, error) {
	rows, err := tx.Query(ctx, `
		SELECT r.id::text, r.workspace_id::text, r.name, r.enabled, r.condition, r.host_ids::text[], r.notify_on_resolve,
		       EXISTS (SELECT 1 FROM alert_rule_channels rc
		               JOIN notification_channels c ON c.id = rc.channel_id AND c.enabled
		               WHERE rc.rule_id = r.id)
		FROM alert_rules r
		WHERE ($1::uuid IS NULL OR r.workspace_id = $1::uuid)
		  AND (r.enabled OR EXISTS (SELECT 1 FROM alert_instances i WHERE i.rule_id = r.id AND i.state = 'firing'))
		ORDER BY r.created_at, r.id
	`, owner)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (*ruleRow, error) {
		r := &ruleRow{}
		err := row.Scan(&r.id, &r.workspaceID, &r.name, &r.enabled, &r.condition, &r.hostIDs, &r.notifyOnResolve, &r.hasChannels)
		return r, err
	})
}

func evaluateRule(ctx context.Context, tx pgx.Tx, r *ruleRow, host *string, now time.Time, res *RuleEvalResult) error {
	// Hosts of the owner (one, or all) with their status for this rule.
	rows, err := tx.Query(ctx, alertRuleHostsSQL, r.workspaceID, host, r.hostIDs)
	if err != nil {
		return err
	}
	r.hosts = map[string]hostRef{}
	r.status = map[string]alerting.HostStatus{}
	for rows.Next() {
		var h hostRef
		var archived, inScope bool
		if err := rows.Scan(&h.id, &h.hostname, &h.label, &archived, &inScope); err != nil {
			rows.Close()
			return err
		}
		r.hosts[h.id] = h
		switch {
		case archived:
			r.status[h.id] = alerting.ReasonHostArchived
		case !inScope:
			r.status[h.id] = alerting.ReasonOutOfScope
		default:
			r.status[h.id] = alerting.HostOK
			r.evaluatedHostIDs = append(r.evaluatedHostIDs, h.id)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	rows, err = tx.Query(ctx, `
		SELECT id::text, host_id::text, subject, condition, title, details
		FROM alert_instances
		WHERE rule_id = $1 AND state = 'firing' AND ($2::uuid IS NULL OR host_id = $2::uuid)
		ORDER BY fired_at, id
	`, r.id, host)
	if err != nil {
		return err
	}
	for rows.Next() {
		var f alerting.Firing
		if err := rows.Scan(&f.ID, &f.HostID, &f.Subject, &f.Condition, &f.Title, &f.Details); err != nil {
			rows.Close()
			return err
		}
		r.firing = append(r.firing, f)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	var plan alerting.Plan
	if !r.enabled {
		for _, f := range r.firing {
			plan.Resolve = append(plan.Resolve, alerting.Resolution{ID: f.ID, Reason: alerting.ReasonRuleDisabled})
		}
	} else {
		c, err := alerting.ParseCondition(r.condition)
		if err != nil {
			// Written by something other than the dashboard's validator:
			// leave its alerts as they are rather than guess.
			log.Printf("alert rule %s (%q): invalid condition, skipped: %v", r.id, r.name, err)
			return nil
		}
		r.parsed = c
		var er alerting.Result
		if len(r.evaluatedHostIDs) > 0 {
			eval, ok := propertyEvaluators[c.Property]
			if !ok {
				return fmt.Errorf("no evaluator for property %q", c.Property)
			}
			if er, err = eval(ctx, tx, c, r.evaluatedHostIDs, now); err != nil {
				return err
			}
		}
		plan = alerting.Diff(r.firing, er, r.status, c.JSON())
	}
	res.Rules++
	return applyPlan(ctx, tx, r, plan, now, res)
}

// eventPayload is the notify.Event body of a transition (ID, type, time
// and URL are filled in when it is sent).
func eventPayload(r *ruleRow, property string, inst notify.Alert, hostID string, details json.RawMessage) ([]byte, error) {
	ev := notify.Event{Alert: &inst}
	if h, ok := r.hosts[hostID]; ok {
		ev.Host = &notify.Host{ID: h.id, Hostname: h.hostname, Label: h.label}
	}
	if property == alerting.PropVulnerability && len(details) > 0 {
		var f notify.Finding
		if err := json.Unmarshal(details, &f); err == nil {
			ev.Finding = &f
		}
	}
	return json.Marshal(ev)
}

func applyPlan(ctx context.Context, tx pgx.Tx, r *ruleRow, p alerting.Plan, now time.Time, res *RuleEvalResult) error {
	var evInstances, evTypes []string
	var evPayloads [][]byte
	addEvent := func(id, typ string, payload []byte) {
		evInstances, evTypes, evPayloads = append(evInstances, id), append(evTypes, typ), append(evPayloads, payload)
	}

	if len(p.Fire) > 0 {
		hosts := make([]string, len(p.Fire))
		subjects := make([]string, len(p.Fire))
		titles := make([]string, len(p.Fire))
		dets := make([][]byte, len(p.Fire))
		for i, m := range p.Fire {
			hosts[i], subjects[i], titles[i] = m.HostID, m.Subject, m.Title
			dets[i] = orEmptyObject(m.Details)
		}
		rows, err := tx.Query(ctx, `
			INSERT INTO alert_instances (workspace_id, rule_id, rule_name, host_id, subject, property, condition,
			                             state, title, details, fired_at, updated_at)
			SELECT $1, $2, $3, m.host_id, m.subject, $4, $5, 'firing', m.title, m.details, $6, $6
			FROM unnest($7::uuid[], $8::text[], $9::text[], $10::jsonb[]) WITH ORDINALITY AS m(host_id, subject, title, details, n)
			ORDER BY m.n
			RETURNING id::text
		`, r.workspaceID, r.id, r.name, r.parsed.Property, r.parsed.JSON(), now, hosts, subjects, titles, dets)
		if err != nil {
			return fmt.Errorf("fire: %w", err)
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		if len(ids) != len(p.Fire) {
			return fmt.Errorf("fire: inserted %d of %d", len(ids), len(p.Fire))
		}
		res.Fired += len(ids)
		if r.hasChannels {
			for i, m := range p.Fire {
				payload, err := eventPayload(r, r.parsed.Property, notify.Alert{
					ID: ids[i], Property: r.parsed.Property, Subject: m.Subject, Title: m.Title,
					State: alerting.StateFiring, FiredAt: now, Details: dets[i],
				}, m.HostID, dets[i])
				if err != nil {
					return err
				}
				addEvent(ids[i], notify.EventAlertFiring, payload)
			}
		}
	}

	if len(p.Refresh) > 0 {
		ids := make([]string, len(p.Refresh))
		titles := make([]string, len(p.Refresh))
		dets := make([][]byte, len(p.Refresh))
		for i, u := range p.Refresh {
			ids[i], titles[i], dets[i] = u.ID, u.Match.Title, orEmptyObject(u.Match.Details)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE alert_instances i SET title = u.title, details = u.details, condition = $4, updated_at = $5
			FROM unnest($1::uuid[], $2::text[], $3::jsonb[]) AS u(id, title, details)
			WHERE i.id = u.id
		`, ids, titles, dets, r.parsed.JSON(), now); err != nil {
			return fmt.Errorf("refresh: %w", err)
		}
		res.Refreshed += len(ids)
	}

	if len(p.Resolve) > 0 {
		ids := make([]string, len(p.Resolve))
		reasons := make([]string, len(p.Resolve))
		for i, x := range p.Resolve {
			ids[i], reasons[i] = x.ID, x.Reason
		}
		rows, err := tx.Query(ctx, `
			UPDATE alert_instances i SET state = 'resolved', resolved_at = $3, resolved_reason = x.reason
			FROM unnest($1::uuid[], $2::text[]) AS x(id, reason)
			WHERE i.id = x.id AND i.state = 'firing'
			RETURNING i.id::text, i.host_id::text, i.subject, i.property, i.title, i.details, i.fired_at, x.reason
		`, ids, reasons, now)
		if err != nil {
			return fmt.Errorf("resolve: %w", err)
		}
		type resolved struct {
			id, host, subject, property, title, reason string
			details                                    []byte
			firedAt                                    time.Time
		}
		done, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (resolved, error) {
			var x resolved
			err := row.Scan(&x.id, &x.host, &x.subject, &x.property, &x.title, &x.details, &x.firedAt, &x.reason)
			return x, err
		})
		if err != nil {
			return err
		}
		res.Resolved += len(done)
		if r.hasChannels && r.notifyOnResolve {
			for _, x := range done {
				if !alerting.Notifies(x.reason) {
					continue
				}
				at := now
				payload, err := eventPayload(r, x.property, notify.Alert{
					ID: x.id, Property: x.property, Subject: x.subject, Title: x.title,
					State: alerting.StateResolved, FiredAt: x.firedAt.UTC(), ResolvedAt: &at, Details: x.details,
				}, x.host, x.details)
				if err != nil {
					return err
				}
				addEvent(x.id, notify.EventAlertResolved, payload)
			}
		}
	}

	if len(evInstances) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO alert_events (workspace_id, rule_id, instance_id, type, occurred_at, payload)
			SELECT $1, $2, e.instance_id, e.type, $3, e.payload
			FROM unnest($4::uuid[], $5::text[], $6::jsonb[]) WITH ORDINALITY AS e(instance_id, type, payload, n)
			ORDER BY e.n
		`, r.workspaceID, r.id, now, evInstances, evTypes, evPayloads); err != nil {
			return fmt.Errorf("alert events: %w", err)
		}
		res.Events += len(evInstances)
	}
	return nil
}

func orEmptyObject(b []byte) []byte {
	if len(b) == 0 {
		return []byte("{}")
	}
	return b
}
