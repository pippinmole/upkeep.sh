package registry

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Anonymous registry auth (the distribution token flow): a request
// without a token gets 401 with
//
//	WWW-Authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/postgres:pull"
//
// and the client GETs realm?service=…&scope=… for a short-lived token,
// then repeats the request with "Authorization: Bearer <token>". The
// scope we ask for is always pull on the one repository being read,
// whatever the challenge says. Basic challenges (credentials required)
// mean the image is private.

// dockerHubAuthHost is the only token endpoint the platform's Docker Hub
// credentials are ever sent to.
const dockerHubAuthHost = "auth.docker.io"

const (
	maxTokenBytes   = 1 << 20
	maxCachedTokens = 256 // expired ones are pruned beyond this
)

type tokenKey struct{ host, repository string }

type token struct {
	value   string
	expires time.Time
}

// cachedToken returns a still-valid token for ref's repository.
func (c *Client) cachedToken(ref Ref) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.tokens[tokenKey{ref.Host, ref.Repository}]
	if !ok || !c.cfg.Now().Before(t.expires) {
		return ""
	}
	return t.value
}

// parseChallenge parses a WWW-Authenticate header into its scheme
// (lowercased) and parameters (keys lowercased). Values may be quoted and
// contain commas.
func parseChallenge(h string) (scheme string, params map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	params = map[string]string{}
	for rest = strings.TrimSpace(rest); rest != ""; {
		key, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		key = strings.ToLower(strings.TrimSpace(key))
		var val string
		if strings.HasPrefix(after, `"`) {
			var b strings.Builder
			i := 1
			for ; i < len(after) && after[i] != '"'; i++ {
				if after[i] == '\\' && i+1 < len(after) {
					i++
				}
				b.WriteByte(after[i])
			}
			val, rest = b.String(), after[min(i+1, len(after)):]
		} else {
			val, rest, _ = strings.Cut(after, ",")
			val = strings.TrimSpace(val)
		}
		params[key] = val
		rest = strings.TrimLeft(rest, ", ")
	}
	return strings.ToLower(scheme), params
}

// fetchToken runs the token flow for ref after a 401 with challenge h and
// caches the token. A Basic (or unknown) challenge, or a token endpoint
// that refuses, is KindDenied.
func (c *Client) fetchToken(ctx context.Context, ref Ref, h string) (string, error) {
	scheme, params := parseChallenge(h)
	if scheme != "bearer" || params["realm"] == "" {
		return "", newErr(KindDenied, ref.Host, "authentication required (%s challenge)", cmp.Or(scheme, "no"))
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Host == "" {
		return "", newErr(KindTransient, ref.Host, "bad token realm %q", params["realm"])
	}
	q := realm.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", "repository:"+ref.Repository+":pull")
	realm.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", newErr(KindTransient, ref.Host, "token request: %v", err)
	}
	if c.cfg.DockerHubToken != "" && ref.IsDockerHub() && strings.EqualFold(realm.Hostname(), dockerHubAuthHost) &&
		realm.Scheme == "https" {
		req.SetBasicAuth(c.cfg.DockerHubUsername, c.cfg.DockerHubToken)
	}
	body, _, err := c.send(ctx, ref.Host, req, maxTokenBytes, c.cfg.RequestTimeout)
	if err != nil {
		return "", err
	}
	var tr struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", newErr(KindTransient, ref.Host, "token response: %v", err)
	}
	tok := cmp.Or(tr.Token, tr.AccessToken)
	if tok == "" {
		return "", newErr(KindTransient, ref.Host, "token response without a token")
	}
	// Tokens live 60s by default (spec); keep a margin.
	ttl := time.Duration(max(tr.ExpiresIn, 60))*time.Second - 10*time.Second
	c.mu.Lock()
	now := c.cfg.Now()
	if len(c.tokens) >= maxCachedTokens {
		for k, t := range c.tokens {
			if !now.Before(t.expires) {
				delete(c.tokens, k)
			}
		}
	}
	c.tokens[tokenKey{ref.Host, ref.Repository}] = token{tok, now.Add(ttl)}
	c.mu.Unlock()
	return tok, nil
}
