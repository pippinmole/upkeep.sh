// Package email is the "email" channel type: an email sent through the
// user's own SMTP server (settings are per channel; there is no
// platform-wide SMTP config). Alerts, digests and tests are plain text
// rendered for humans like ntfy: a subject line naming what happened, a
// short body and a link to the dashboard. Reports are HTML with a
// plain-text alternative, rendered by web (render.go). Format, security
// modes and error handling: docs/ARCHITECTURE.md "Email (SMTP) channel".
//
// Connections go through netguard.Guard.DialSMTP (ports 25, 465, 587, 2525;
// public addresses only, checked at dial time) and the stdlib net/smtp
// client runs over that connection. net/smtp's own PLAIN auth refuses
// unencrypted non-localhost connections on its own terms; this package
// uses its own PLAIN/LOGIN implementations and decides explicitly: over a
// connection without TLS, credentials are only sent when the channel's
// "Allow insecure authentication" setting is on. TLS certificates are
// always verified.
package email

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/notify/render"
	"github.com/pippinmole/upkeep.sh/server/internal/reports"
)

const (
	Type = "email"

	// Timeout bounds one attempt: connect, TLS, the SMTP conversation.
	Timeout = 30 * time.Second

	// DefaultPort is used when the port is blank (DefaultTLSPort in TLS mode).
	DefaultPort    = 587
	DefaultTLSPort = 465

	// MaxRecipients caps the To list.
	MaxRecipients = 20

	// FromName is the display name on the From header.
	FromName = "upkeep.sh"
	// SubjectPrefix starts every subject, for mail filters.
	SubjectPrefix = "[upkeep.sh] "

	maxSubject = 200 // bytes, before the prefix and RFC 2047 encoding
	maxListed  = 50  // events listed in a multi-event message
	maxReply   = 300 // bytes of an SMTP reply kept in an error
)

// Security modes (the "security" field).
const (
	SecurityStartTLS = "starttls" // plaintext connect, STARTTLS required
	SecurityTLS      = "tls"      // implicit TLS from the first byte
	SecurityNone     = "none"     // no TLS at all
)

// ErrInsecureAuth is returned (as a permanent error) when credentials would
// be sent over a connection without TLS and the channel doesn't allow it.
var ErrInsecureAuth = errors.New("refusing to send the SMTP username and password over a connection that is not " +
	"TLS-protected: choose security STARTTLS or TLS, or turn on \"Allow insecure authentication\" " +
	"if the server is on a network you trust")

// Notifier is the email channel type.
type Notifier struct {
	Guard *netguard.Guard
	// Now is the Date header clock (tests); nil = time.Now.
	Now func() time.Time
	// Reports renders report emails (HTML + text) through web; nil = not
	// configured, report emails are plain text.
	Reports *ReportRenderer
}

// plainReportsOnce logs, once per process, that report emails are plain
// text because the renderer isn't configured.
var plainReportsOnce sync.Once

func New(g *netguard.Guard) *Notifier { return &Notifier{Guard: g} }

func (n *Notifier) Spec() notify.Spec {
	return notify.Spec{
		Type:        Type,
		Label:       "Email",
		Description: "Plain-text email sent through your own SMTP server (your mail provider, a transactional mail service, or your own relay).",
		Fields: []notify.Field{
			{
				Key: "to", Label: "To", Type: notify.FieldText, Required: true, MaxLength: 2048,
				Placeholder: "ops@example.com, oncall@example.com",
				Help:        fmt.Sprintf("One or more recipient addresses, separated by commas (at most %d).", MaxRecipients),
			},
			{
				Key: "from", Label: "From address", Type: notify.FieldEmail, Required: true, MaxLength: 254,
				Placeholder: "alerts@example.com",
				Help:        "The sender address. Most providers only accept addresses on a domain you have verified with them.",
			},
			{
				Key: "host", Label: "SMTP server", Type: notify.FieldText, Required: true, MaxLength: 253,
				Placeholder: "smtp.example.com",
				Help: "Host name of your SMTP server. It must be reachable on a public address; " +
					"private and internal addresses are refused.",
			},
			{
				Key: "port", Label: "Port", Type: notify.FieldText, MaxLength: 5,
				Placeholder: strconv.Itoa(DefaultPort),
				Help: "25, 465, 587 or 2525. Leave blank for 587 (465 when security is TLS). " +
					"Usually 587 with STARTTLS or 465 with TLS.",
			},
			{
				Key: "security", Label: "Security", Type: notify.FieldSelect,
				Placeholder: "STARTTLS (recommended)",
				Help: "STARTTLS: connect in plain text, then upgrade to TLS; fails if the server doesn't offer it. " +
					"TLS: encrypted from the start (usually port 465). None: no encryption, for relays on a network you trust. " +
					"Certificates are always verified.",
				Options: []notify.Option{
					{Value: SecurityStartTLS, Label: "STARTTLS (recommended)"},
					{Value: SecurityTLS, Label: "TLS (implicit, usually port 465)"},
					{Value: SecurityNone, Label: "None (unencrypted)"},
				},
			},
			{
				Key: "username", Label: "Username", Type: notify.FieldText, MaxLength: 256,
				Placeholder: "alerts@example.com",
				Help:        "Optional. Leave blank if your server accepts mail without logging in.",
			},
			{
				Key: "password", Label: "Password", Type: notify.FieldSecret, Secret: true, MaxLength: 256,
				Help: "Required with a username; an app password or API key for most providers.",
			},
			{
				Key: "allow_insecure_auth", Label: "Allow insecure authentication", Type: notify.FieldBool,
				Help: "Off (recommended): the username and password are only ever sent over TLS, so with " +
					"security None and a username the channel won't send. On: allow logging in over an " +
					"unencrypted connection, where anyone on the network path can read the password.",
			},
		},
	}
}

// settings is a validated channel config.
type settings struct {
	host         string // as entered (IPv6 without brackets)
	port         int
	security     string
	username     string
	password     string
	from         string
	to           []string
	insecureAuth bool
}

func (n *Notifier) Validate(cfg notify.Config) error {
	_, err := n.parse(cfg)
	return err
}

func (n *Notifier) parse(cfg notify.Config) (settings, error) {
	var s settings
	if err := notify.ValidateRequired(n.Spec(), cfg); err != nil {
		return s, err
	}
	s.security = strings.TrimSpace(cfg["security"])
	if s.security == "" {
		s.security = SecurityStartTLS
	}
	s.port = DefaultPort
	if s.security == SecurityTLS {
		s.port = DefaultTLSPort
	}
	if p := strings.TrimSpace(cfg["port"]); p != "" {
		v, err := strconv.Atoi(p)
		if err != nil || v < 1 || v > 65535 {
			return s, fmt.Errorf("port %q is not a valid port number", p)
		}
		s.port = v
	}
	s.host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(cfg["host"]), "["), "]")
	if hasControl(s.host) {
		return s, errors.New("SMTP server must not contain spaces or control characters")
	}
	if err := n.Guard.CheckSMTP(s.host, s.port); err != nil {
		return s, fmt.Errorf("SMTP server: %w", err)
	}

	from, err := checkAddress(cfg["from"])
	if err != nil {
		return s, fmt.Errorf("from address: %w", err)
	}
	s.from = from
	if s.to, err = parseRecipients(cfg["to"]); err != nil {
		return s, err
	}

	s.username, s.password = cfg["username"], cfg["password"]
	for _, v := range []struct{ name, val string }{{"username", s.username}, {"password", s.password}} {
		if strings.ContainsAny(v.val, "\r\n\x00") {
			return s, fmt.Errorf("%s must not contain line breaks or NUL characters", v.name)
		}
	}
	switch {
	case s.username != "" && s.password == "":
		return s, errors.New("password is required when a username is set")
	case s.username == "" && s.password != "":
		return s, errors.New("username is required when a password is set")
	}

	switch v := cfg["allow_insecure_auth"]; v {
	case "", "false":
	case "true":
		s.insecureAuth = true
	default:
		return s, fmt.Errorf("allow insecure authentication: invalid value %q", v)
	}
	if s.security == SecurityNone && s.username != "" && !s.insecureAuth {
		return s, errors.New("security is None, so the password would be sent unencrypted: choose STARTTLS or TLS, " +
			"or turn on \"Allow insecure authentication\" if the server is on a network you trust")
	}
	return s, nil
}

// hasControl reports whether s has whitespace or control characters.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

// checkAddress accepts one bare ASCII address ("ops@example.com", no
// display name). CR/LF and other control characters are refused, so an
// address can never break out of a header or an SMTP command.
func checkAddress(raw string) (string, error) {
	a := strings.TrimSpace(raw)
	if a == "" {
		return "", errors.New("address is empty")
	}
	if hasControl(a) {
		return "", fmt.Errorf("%q must not contain spaces, line breaks or control characters", a)
	}
	for _, r := range a {
		if r > unicode.MaxASCII {
			return "", fmt.Errorf("%q: only ASCII addresses are supported", a)
		}
	}
	p, err := mail.ParseAddress(a)
	if err != nil || p.Name != "" || p.Address != a || strings.ContainsAny(a, `<>"(),;:\[]`) {
		return "", fmt.Errorf("%q is not a valid email address (use a bare address like ops@example.com)", a)
	}
	at := strings.LastIndexByte(a, '@')
	if at < 1 || at == len(a)-1 {
		return "", fmt.Errorf("%q is not a valid email address", a)
	}
	return a, nil
}

// parseRecipients splits the To field on commas and semicolons and checks
// each address; duplicates are dropped.
func parseRecipients(raw string) ([]string, error) {
	if strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errors.New("to: addresses must not contain line breaks")
	}
	var out []string
	for part := range strings.FieldsFuncSeq(raw, func(r rune) bool { return r == ',' || r == ';' }) {
		if strings.TrimSpace(part) == "" {
			continue
		}
		a, err := checkAddress(part)
		if err != nil {
			return nil, fmt.Errorf("to: %w", err)
		}
		if !slices.ContainsFunc(out, func(o string) bool { return strings.EqualFold(o, a) }) {
			out = append(out, a)
		}
	}
	switch {
	case len(out) == 0:
		return nil, errors.New("to: at least one recipient address is required")
	case len(out) > MaxRecipients:
		return nil, fmt.Errorf("to: at most %d recipients", MaxRecipients)
	}
	return out, nil
}

// ---- Rendering ----

// Message is a rendered email: the subject (before encoding) and the
// plain-text body.
type Message struct {
	Subject string
	Body    string
}

// Render turns a notification into an email subject and body.
func Render(n notify.Notification) Message {
	var subject string
	var b strings.Builder
	link := ""
	switch {
	case n.Kind == notify.KindTest:
		subject = n.Summary
		if subject == "" {
			subject = "Test notification from upkeep.sh"
		}
		b.WriteString("This is a test email from upkeep.sh.\n\n" +
			"Your email channel works: alerts matching your rules will be delivered to this address.")
	case n.Kind == notify.KindReport:
		// The plain-text report, used only when the worker has no
		// ReportRenderer; otherwise web renders it (Notifier.Send).
		subject = n.Summary
		if n.Report != nil && n.Report.Snapshot != nil {
			subject = reports.Title(*n.Report.Snapshot)
			b.WriteString(subject + "\n\n" + render.ReportHeadline(*n.Report.Snapshot))
			link = n.Report.URL
		} else {
			b.WriteString(subject)
		}
	case len(n.Events) == 1:
		e := n.Events[0]
		subject = render.Title(e)
		b.WriteString(render.Title(e) + "\n\n" + render.Body(e))
		link = e.URL
	default:
		subject = n.Summary
		if subject == "" {
			subject = fmt.Sprintf("%d events", len(n.Events))
		}
		b.WriteString(subject + "\n\n" + render.List(n.Events, maxListed))
		link = render.CommonURL(n.Events)
	}
	if n.Kind == notify.KindDigest && !strings.HasPrefix(subject, "Digest: ") {
		subject = "Digest: " + subject
	}
	if link != "" {
		b.WriteString("\n\nOpen in upkeep.sh: " + link)
	}
	if n.Rule != nil && n.Rule.Name != "" {
		b.WriteString("\n\nRule: " + n.Rule.Name)
	}
	if n.Kind == notify.KindReport {
		b.WriteString("\n\n-- \nSent by upkeep.sh. Change your reports under Settings > Notification settings in the dashboard.\n")
	} else {
		b.WriteString("\n\n-- \nSent by upkeep.sh. Change what you're alerted about under Alerts in the dashboard.\n")
	}
	return Message{Subject: render.Truncate(sanitizeHeader(subject), maxSubject), Body: b.String()}
}

// sanitizeHeader replaces control characters (CR, LF, tab, ...) with
// spaces and collapses runs of spaces, so text from events (package,
// host and agent names) can't start a new header line.
func sanitizeHeader(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

var tokenRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// header appends "Name: value\r\n", refusing values with CR or LF (every
// value is validated or sanitized before this; this is the last line of
// defense against header injection).
func header(b *strings.Builder, name, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("email: header %s contains a line break", name)
	}
	b.WriteString(name + ": " + value + "\r\n")
	return nil
}

// buildMessage renders the RFC 5322 message: headers, then the body as
// quoted-printable UTF-8 text. With rep (a report rendered by web) it is
// multipart/alternative instead: the text part, then the HTML part.
func (n *Notifier) buildMessage(s settings, note notify.Notification, rep *RenderedReport) ([]byte, error) {
	var subject, contentType, body, boundary string
	var err error
	if rep != nil {
		subject = rep.Subject // already prefixed and sanitized (ReportRenderer.Render)
		if body, boundary, err = multipartBody(rep.Text, rep.HTML); err != nil {
			return nil, err
		}
		contentType = mime.FormatMediaType("multipart/alternative", map[string]string{"boundary": boundary})
	} else {
		m := Render(note)
		subject, contentType = SubjectPrefix+m.Subject, "text/plain; charset=utf-8"
		if body, err = qpEncode(m.Body); err != nil {
			return nil, err
		}
	}
	now := time.Now
	if n.Now != nil {
		now = n.Now
	}
	domain := s.from[strings.LastIndexByte(s.from, '@')+1:]
	id := note.DeliveryID
	if !tokenRE.MatchString(id) {
		id = randomHex(16)
	}

	var h strings.Builder
	from := (&mail.Address{Name: FromName, Address: s.from}).String()
	for _, kv := range [][2]string{
		{"From", from},
		{"To", strings.Join(s.to, ", ")},
		{"Subject", mime.QEncoding.Encode("utf-8", subject)},
		{"Date", now().Format(time.RFC1123Z)},
		{"Message-ID", "<" + id + "@" + domain + ">"},
		{"MIME-Version", "1.0"},
		{"Content-Type", contentType},
	} {
		if err := header(&h, kv[0], kv[1]); err != nil {
			return nil, err
		}
	}
	if rep == nil {
		_ = header(&h, "Content-Transfer-Encoding", "quoted-printable")
	}
	_ = header(&h, "Auto-Submitted", "auto-generated")
	if tokenRE.MatchString(note.Kind) {
		_ = header(&h, "X-Upkeep-Kind", note.Kind)
	}
	if tokenRE.MatchString(note.DeliveryID) {
		_ = header(&h, "X-Upkeep-Delivery", note.DeliveryID)
	}
	h.WriteString("\r\n")
	return []byte(h.String() + body), nil
}

// qpEncode is text as quoted-printable UTF-8 with CRLF line breaks.
func qpEncode(text string) (string, error) {
	var b strings.Builder
	qp := quotedprintable.NewWriter(&b)
	if _, err := io.WriteString(qp, strings.ToValidUTF8(text, "�")); err != nil {
		return "", err
	}
	if err := qp.Close(); err != nil {
		return "", err
	}
	return b.String(), nil
}

func randomHex(n int) string {
	r := make([]byte, n)
	_, _ = rand.Read(r)
	return hex.EncodeToString(r)
}

// multipartBody is a multipart/alternative body (text/plain, then
// text/html, both quoted-printable UTF-8) and its boundary. The
// boundary is random and starts with "=_", which quoted-printable output
// can never contain ("=" is always followed by hex digits or a line
// break); it is still checked against both parts.
func multipartBody(text, html string) (body, boundary string, err error) {
	var parts [2]string
	for i, p := range []string{text, html} {
		if parts[i], err = qpEncode(p); err != nil {
			return "", "", err
		}
	}
	boundary = "=_upkeep_" + randomHex(16)
	if strings.Contains(parts[0], boundary) || strings.Contains(parts[1], boundary) {
		return "", "", errors.New("email: MIME boundary collision") // practically impossible
	}
	var w strings.Builder
	for i, ct := range []string{"text/plain; charset=utf-8", "text/html; charset=utf-8"} {
		w.WriteString("--" + boundary + "\r\n" +
			"Content-Type: " + ct + "\r\n" +
			"Content-Transfer-Encoding: quoted-printable\r\n\r\n" +
			parts[i] + "\r\n")
	}
	w.WriteString("--" + boundary + "--\r\n")
	return w.String(), boundary, nil
}

// ---- Delivery ----

func (n *Notifier) tlsConfig(host string) *tls.Config {
	var c *tls.Config
	if n.Guard != nil && n.Guard.TLSConfig != nil {
		c = n.Guard.TLSConfig.Clone()
	} else {
		c = &tls.Config{}
	}
	c.ServerName = host
	c.InsecureSkipVerify = false // certificates are always verified
	if c.MinVersion == 0 {
		c.MinVersion = tls.VersionTLS12
	}
	return c
}

func (n *Notifier) Send(ctx context.Context, cfg notify.Config, note notify.Notification) (notify.Result, error) {
	var res notify.Result
	s, err := n.parse(cfg)
	if err != nil {
		return res, notify.Permanent(err)
	}
	var rep *RenderedReport
	if note.Kind == notify.KindReport && note.Report != nil && note.Report.Snapshot != nil {
		if n.Reports == nil {
			plainReportsOnce.Do(func() { log.Printf("email: %v", errRenderNotConfigured) })
		} else {
			r, err := n.Reports.Render(ctx, note.Report.Snapshot, note.Report.URL)
			if err != nil {
				return res, fmt.Errorf("email: %w", err) // retried, never permanent
			}
			rep = &r
		}
	}
	msg, err := n.buildMessage(s, note, rep)
	if err != nil {
		return res, notify.Permanent(err)
	}
	return res, n.deliver(ctx, s, msg)
}

// deliver runs one SMTP conversation for a validated config.
func (n *Notifier) deliver(ctx context.Context, s settings, msg []byte) error {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))
	conn, err := n.Guard.DialSMTP(ctx, s.host, s.port)
	if err != nil {
		return classify("connect to "+addr, err, s)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	// Cancellation interrupts any blocked read or write.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if s.security == SecurityTLS {
		tc := tls.Client(conn, n.tlsConfig(s.host))
		if err := tc.HandshakeContext(ctx); err != nil {
			return classify("TLS handshake with "+addr, err, s)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return classify("greeting from "+addr, err, s)
	}
	defer c.Close()
	if err := c.Hello(s.from[strings.LastIndexByte(s.from, '@')+1:]); err != nil {
		return classify("EHLO", err, s)
	}

	if s.security == SecurityStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return notify.Permanent(fmt.Errorf("email: %s does not offer STARTTLS, which security mode STARTTLS "+
				"requires: use security TLS if the server expects TLS from the start (usually port 465)", addr))
		}
		if err := c.StartTLS(n.tlsConfig(s.host)); err != nil {
			return classify("STARTTLS", err, s)
		}
	}

	if s.username != "" {
		// Checked on the live connection, not just the configured mode.
		if _, isTLS := c.TLSConnectionState(); !isTLS && !s.insecureAuth {
			return notify.Permanent(fmt.Errorf("email: %w", ErrInsecureAuth))
		}
		ok, mechs := c.Extension("AUTH")
		if !ok {
			return notify.Permanent(fmt.Errorf("email: %s does not offer authentication (AUTH); "+
				"clear the username and password if it accepts mail without logging in", addr))
		}
		a := pickAuth(mechs, s.username, s.password)
		if a == nil {
			return notify.Permanent(fmt.Errorf("email: %s offers no supported login mechanism "+
				"(want PLAIN or LOGIN, server offers %q)", addr, mechs))
		}
		if err := c.Auth(a); err != nil {
			return classify("authentication failed", err, s)
		}
	}

	if err := c.Mail(s.from); err != nil {
		return classify("MAIL FROM <"+s.from+">", err, s)
	}
	for _, to := range s.to {
		if err := c.Rcpt(to); err != nil {
			return classify("RCPT TO <"+to+">", err, s)
		}
	}
	w, err := c.Data()
	if err != nil {
		return classify("DATA", err, s)
	}
	if _, err := w.Write(msg); err != nil {
		return classify("sending the message", err, s)
	}
	if err := w.Close(); err != nil {
		return classify("message rejected", err, s)
	}
	_ = c.Quit() // the message was accepted; a failed QUIT doesn't matter
	return nil
}

// classify turns an SMTP conversation error into a notify error:
//
//	4xx reply, connection errors, timeouts   retried
//	5xx reply (incl. failed login)           permanent
//	blocked destination, TLS certificate
//	or protocol mismatch, other refusals     permanent
func classify(step string, err error, s settings) error {
	var tpe *textproto.Error
	if errors.As(err, &tpe) {
		e := fmt.Errorf("email: %s: SMTP %d %s", step, tpe.Code, replyText(tpe.Msg))
		if tpe.Code >= 400 && tpe.Code < 500 {
			return e
		}
		return notify.Permanent(e)
	}
	if errors.Is(err, netguard.ErrBlocked) {
		return notify.Permanent(fmt.Errorf("email: %s: %w", step, err))
	}
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) {
		return notify.Permanent(fmt.Errorf("email: %s: TLS certificate verification failed: %w", step, err))
	}
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		return notify.Permanent(fmt.Errorf("email: %s: the server did not answer with TLS (%w); "+
			"check the port and security mode (TLS is usually port 465, STARTTLS port 587)", step, err))
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() && s.security != SecurityTLS && s.port == DefaultTLSPort {
		return fmt.Errorf("email: %s: %w (port 465 usually needs security mode TLS)", step, err)
	}
	return fmt.Errorf("email: %s: %w", step, err)
}

// replyText is an SMTP reply's text on one line, cut to maxReply bytes.
func replyText(msg string) string {
	msg = sanitizeHeader(strings.ToValidUTF8(msg, "�"))
	if msg == "" {
		return "(no text)"
	}
	return render.Truncate(msg, maxReply)
}

// pickAuth chooses PLAIN, else LOGIN, from the server's AUTH mechanisms.
// These implementations don't check for TLS themselves (unlike
// smtp.PlainAuth): Send has already applied the insecure-auth rule.
func pickAuth(mechs, user, pass string) smtp.Auth {
	offered := strings.Fields(strings.ToUpper(mechs))
	switch {
	case slices.Contains(offered, "PLAIN"):
		return plainAuth{user, pass}
	case slices.Contains(offered, "LOGIN"):
		return &loginAuth{user: user, pass: pass}
	}
	return nil
}

type plainAuth struct{ user, pass string }

func (a plainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
}

func (a plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge during AUTH PLAIN")
	}
	return nil, nil
}

type loginAuth struct {
	user, pass string
	step       int
}

func (a *loginAuth) Start(*smtp.ServerInfo) (string, []byte, error) { return "LOGIN", nil, nil }

func (a *loginAuth) Next(challenge []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	p := strings.ToLower(strings.TrimSpace(string(challenge)))
	switch {
	case strings.HasPrefix(p, "username"), p == "" && a.step == 1:
		return []byte(a.user), nil
	case strings.HasPrefix(p, "password"), p == "" && a.step == 2:
		return []byte(a.pass), nil
	}
	return nil, fmt.Errorf("unexpected AUTH LOGIN challenge %q", replyText(string(challenge)))
}
