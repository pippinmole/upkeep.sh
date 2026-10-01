package main

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/pippinmole/upkeep.sh/agent/internal/snapshot"
	"github.com/pippinmole/upkeep.sh/agent/internal/target"
	"github.com/pippinmole/upkeep.sh/agent/internal/transport"
)

// Remote targets (PROTOCOL.md "Remote targets"). The agent pulls its
// target list from the server every configPollInterval (a cheap 304 when
// nothing changed), so a host added in the dashboard is tried within a
// minute. Each target is then collected on the push interval. A target
// that fails is retried with backoff, starting at configPollInterval and
// capped at the push interval: a quick retry while the user is still
// setting it up, without an SSH login attempt every minute forever (which
// would also trip fail2ban-style lockouts on the remote host).

const configPollInterval = time.Minute

type remoteTarget struct {
	cfg     transport.RemoteTarget
	hostKey ssh.PublicKey // parsed cfg.HostKey; nil if none confirmed
	nextAt  time.Time
	fails   int
}

type remoteRunner struct {
	client   *transport.Client
	signer   ssh.Signer
	pubLine  string
	collect  *snapshot.Collector
	interval time.Duration

	etag        string
	targets     map[string]*remoteTarget
	keyReported bool
	unsupported bool // the server predates remote targets
}

func newRemoteRunner(client *transport.Client, signer ssh.Signer, collect *snapshot.Collector, interval time.Duration) *remoteRunner {
	return &remoteRunner{
		client: client, signer: signer, pubLine: authorizedKeyLine(signer),
		collect: collect, interval: interval, targets: map[string]*remoteTarget{},
	}
}

// poll fetches the target list if it changed. New targets and targets
// whose settings changed (e.g. the user confirmed a host key) are due
// immediately.
func (r *remoteRunner) poll(creds storedCredentials, now time.Time) {
	if r.unsupported {
		return
	}
	cfg, etag, err := r.client.FetchConfig(creds.AgentID, creds.AgentSecret, r.etag)
	if errors.Is(err, transport.ErrRemoteUnsupported) {
		log.Printf("server does not support remote targets; collecting this machine only")
		r.unsupported = true
		return
	} else if err != nil {
		log.Printf("fetch remote targets: %v", err)
		return
	}
	if cfg == nil {
		return // unchanged
	}
	r.etag = etag
	seen := map[string]bool{}
	for _, t := range cfg.Targets {
		if t.Mode != string(target.ModeSSH) || t.Ref == "" || t.Ref == target.LocalRef {
			log.Printf("remote target %q: unsupported mode %q, skipped", t.Ref, t.Mode)
			continue
		}
		seen[t.Ref] = true
		old, ok := r.targets[t.Ref]
		if ok && old.cfg == t {
			continue
		}
		rt := &remoteTarget{cfg: t, nextAt: now}
		if t.HostKey != "" {
			k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.HostKey))
			if err != nil {
				log.Printf("remote target %s: server sent an unparseable host key: %v", t.Ref, err)
				continue
			}
			rt.hostKey = k
		}
		if !ok {
			log.Printf("remote target %s added: %s@%s:%d", t.Ref, t.Username, t.Address, t.Port)
		}
		r.targets[t.Ref] = rt
	}
	for ref := range r.targets {
		if !seen[ref] {
			log.Printf("remote target %s removed", ref)
			delete(r.targets, ref)
		}
	}
}

// runDue collects every target that is due and reports the outcomes (and,
// once, the agent's public key). It returns whether any push asked the
// agent to rotate its credential.
func (r *remoteRunner) runDue(ctx context.Context, creds storedCredentials, now time.Time) (rotate bool) {
	if r.unsupported {
		return false
	}
	var report []transport.TargetStatus
	for _, t := range r.targets {
		if now.Before(t.nextAt) {
			continue
		}
		st, rot := r.run(ctx, creds, t)
		rotate = rotate || rot
		report = append(report, st)
		if st.ErrorCode == "" || st.ErrorCode == target.CodeHostKeyUnconfirmed {
			// Collected, or waiting for the user to confirm the key (a
			// confirmation changes the config, which makes it due again).
			t.fails = 0
			t.nextAt = now.Add(r.interval)
		} else {
			t.fails++
			t.nextAt = now.Add(backoff(t.fails, r.interval))
		}
	}
	if len(report) == 0 && r.keyReported {
		return rotate
	}
	err := r.client.ReportStatus(creds.AgentID, creds.AgentSecret, transport.StatusReport{SSHPublicKey: r.pubLine, Targets: report})
	switch {
	case errors.Is(err, transport.ErrRemoteUnsupported):
		r.unsupported = true
	case err != nil:
		log.Printf("report remote target status: %v", err)
	default:
		r.keyReported = true
	}
	return rotate
}

// backoff is the retry delay after the nth consecutive failure: one poll
// interval, doubling, capped at the push interval.
func backoff(fails int, interval time.Duration) time.Duration {
	d := configPollInterval
	for i := 1; i < fails && d < interval; i++ {
		d *= 2
	}
	return min(d, max(interval, configPollInterval))
}

// run makes one attempt at a target: fetch its host key if none is
// confirmed yet, otherwise connect, collect and push.
func (r *remoteRunner) run(ctx context.Context, creds storedCredentials, t *remoteTarget) (transport.TargetStatus, bool) {
	st := transport.TargetStatus{Ref: t.cfg.Ref}
	cfg := target.SSHConfig{
		Ref: t.cfg.Ref, Address: t.cfg.Address, Port: t.cfg.Port, Username: t.cfg.Username,
		HostKey: t.hostKey, Signer: r.signer,
	}
	fail := func(err error) (transport.TargetStatus, bool) {
		var ce *target.ConnError
		if errors.As(err, &ce) {
			st.ErrorCode = ce.Code
			if ce.HostKey != nil {
				st.HostKey = keyLine(ce.HostKey)
			}
		} else {
			st.ErrorCode = target.CodeUnreachable
		}
		st.Error = err.Error()
		log.Printf("[%s] %s@%s:%d: %v", t.cfg.Ref, t.cfg.Username, t.cfg.Address, t.cfg.Port, err)
		return st, false
	}

	if t.hostKey == nil {
		key, err := target.ProbeHostKey(ctx, cfg)
		if err != nil {
			return fail(err)
		}
		st.ErrorCode, st.HostKey = target.CodeHostKeyUnconfirmed, keyLine(key)
		st.Error = "host key " + ssh.FingerprintSHA256(key) + " waits for confirmation in the dashboard"
		log.Printf("[%s] %q", t.cfg.Ref, st.Error)
		return st, false
	}

	conn, err := target.DialSSH(ctx, cfg)
	if err != nil {
		var ce *target.ConnError
		if errors.As(err, &ce) && ce.Code == target.CodeHostKeyMismatch && ce.HostKey == nil {
			// The host stopped offering the pinned key's type: probe for
			// the key it offers now, so the user has something to confirm.
			if key, perr := target.ProbeHostKey(ctx, cfg); perr == nil {
				ce.HostKey = key
			}
		}
		return fail(err)
	}
	defer conn.Close()

	snap := r.collect.Collect(ctx, conn)
	logCollectorErrors(conn, snap)
	res, err := r.client.PushSnapshot(creds.AgentID, creds.AgentSecret, snap)
	if err != nil {
		st.ErrorCode, st.Error = "push_failed", err.Error()
		log.Printf("[%s] push failed: %v", t.cfg.Ref, err)
		return st, false
	}
	log.Printf("[%s] pushed snapshot: %s@%s, os=%s/%s, %d packages, %d services, %d users",
		t.cfg.Ref, t.cfg.Username, t.cfg.Address, snap.Host.OSFamily, snap.OS.ID, len(snap.Packages), len(snap.Services), len(snap.Users))
	return st, res.RotateCredentials
}

// keyLine is a public key as "type base64".
func keyLine(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}
