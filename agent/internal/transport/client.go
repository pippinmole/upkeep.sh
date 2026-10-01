// Package transport handles the agent's outbound-only HTTPS conversation
// with the platform: one-time enrollment, periodic snapshot pushes,
// credential rotation, and pulling the remote target list (plus reporting
// how reaching each target went).
// The agent never opens a listening port.
package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

type EnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	// Version and Platform describe the agent build; servers that predate
	// them ignore them.
	Version  string `json:"version,omitempty"`
	Platform string `json:"platform,omitempty"`
}

type EnrollResponse struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
}

// Enroll exchanges a one-time enrollment token (generated in the dashboard)
// for a durable agent_id + secret. The secret is stored locally by the
// caller (e.g. in a 0600 file) and never transmitted again in the clear;
// subsequent requests use it as a bearer token over TLS.
func (c *Client) Enroll(in EnrollRequest) (*EnrollResponse, error) {
	body, _ := json.Marshal(in)
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("enroll failed: %s: %s", resp.Status, b)
	}
	var out EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RotateHeader on a push response asks the agent to rotate its credential
// (PROTOCOL.md "Credential rotation").
const RotateHeader = "X-Upkeep-Rotate-Credentials"

// PushResult is what the server said about an accepted push.
type PushResult struct {
	// RotateCredentials: the server asks the agent to rotate its secret now
	// (requested in the dashboard, periodic, or the agent is still using its
	// pre-rotation secret).
	RotateCredentials bool
}

// PushSnapshot sends a fact snapshot for an already-enrolled agent.
func (c *Client) PushSnapshot(agentID, agentSecret string, snap collector.Snapshot) (PushResult, error) {
	body, err := json.Marshal(snap)
	if err != nil {
		return PushResult{}, err
	}
	resp, err := c.post("/v1/snapshots", agentID, agentSecret, body)
	if err != nil {
		return PushResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		return PushResult{}, fmt.Errorf("push snapshot failed: %s: %s", resp.Status, b)
	}
	return PushResult{RotateCredentials: resp.Header.Get(RotateHeader) != ""}, nil
}

// RotateCredentials asks the server for a new secret, authenticating with
// the current one. The old secret stays valid server-side for a short
// grace window (or until the new one is first used), so the caller must
// persist the new secret before using it, and may retry with the old one
// if persisting fails.
func (c *Client) RotateCredentials(agentID, agentSecret string) (*EnrollResponse, error) {
	resp, err := c.post("/v1/agent/rotate", agentID, agentSecret, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("rotate credentials failed: %s: %s", resp.Status, b)
	}
	var out EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.AgentID != agentID || out.AgentSecret == "" {
		return nil, fmt.Errorf("rotate credentials: unexpected response for agent %q", out.AgentID)
	}
	return &out, nil
}

// post sends an authenticated agent request.
func (c *Client) post(path, agentID, agentSecret string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Agent-ID", agentID)
	req.Header.Set("Authorization", "Bearer "+agentSecret)
	return c.HTTPClient.Do(req)
}

// RemoteTarget is one remote host the agent should collect (GET
// /v1/agent/config).
type RemoteTarget struct {
	Ref      string `json:"ref"`
	Mode     string `json:"mode"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	// HostKey is the host key the user confirmed, "" if none yet.
	HostKey string `json:"host_key"`
}

// AgentConfig is the agent's desired state.
type AgentConfig struct {
	Version string         `json:"version"`
	Targets []RemoteTarget `json:"targets"`
}

// ErrRemoteUnsupported: the server predates remote targets.
var ErrRemoteUnsupported = errors.New("server does not support remote targets")

// FetchConfig gets the agent's remote targets. etag is the ETag of the
// config the agent already has ("" for none); when unchanged, it returns
// (nil, etag, nil).
func (c *Client) FetchConfig(agentID, agentSecret, etag string) (*AgentConfig, string, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/v1/agent/config", http.NoBody)
	if err != nil {
		return nil, etag, err
	}
	req.Header.Set("X-Agent-ID", agentID)
	req.Header.Set("Authorization", "Bearer "+agentSecret)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, etag, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, etag, nil
	case http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return nil, etag, ErrRemoteUnsupported
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, etag, fmt.Errorf("fetch config failed: %s: %s", resp.Status, b)
	}
	var out AgentConfig
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, etag, err
	}
	return &out, resp.Header.Get("ETag"), nil
}

// TargetStatus is the outcome of one attempt to reach a remote target.
type TargetStatus struct {
	Ref string `json:"ref"`
	// ErrorCode is "" when the target was reached and collected.
	ErrorCode string `json:"error_code"`
	Error     string `json:"error,omitempty"`
	// HostKey is the key the target presented (authorized_keys format).
	HostKey string `json:"host_key,omitempty"`
}

// StatusReport is POST /v1/agent/status.
type StatusReport struct {
	// SSHPublicKey is the agent's own public key, shown in the dashboard
	// for the remote hosts' authorized_keys.
	SSHPublicKey string         `json:"ssh_public_key,omitempty"`
	Targets      []TargetStatus `json:"targets"`
}

// ReportStatus sends the agent's public key and remote target outcomes.
func (c *Client) ReportStatus(agentID, agentSecret string, rep StatusReport) error {
	if rep.Targets == nil {
		rep.Targets = []TargetStatus{}
	}
	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	resp, err := c.post("/v1/agent/status", agentID, agentSecret, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return ErrRemoteUnsupported
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("report status failed: %s: %s", resp.Status, b)
}
