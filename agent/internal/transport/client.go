// Package transport handles the agent's outbound-only HTTPS conversation
// with the platform: one-time enrollment and periodic snapshot pushes.
// The agent never opens a listening port.
package transport

import (
	"bytes"
	"encoding/json"
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
}

type EnrollResponse struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
}

// Enroll exchanges a one-time enrollment token (generated in the dashboard)
// for a durable agent_id + secret. The secret is stored locally by the
// caller (e.g. in a 0600 file) and never transmitted again in the clear;
// subsequent requests use it as a bearer token over TLS.
func (c *Client) Enroll(token, hostname string) (*EnrollResponse, error) {
	body, _ := json.Marshal(EnrollRequest{EnrollmentToken: token, Hostname: hostname})
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

// PushSnapshot sends a fact snapshot for an already-enrolled agent.
func (c *Client) PushSnapshot(agentID, agentSecret string, snap collector.Snapshot) error {
	body, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/v1/snapshots", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", agentID)
	req.Header.Set("Authorization", "Bearer "+agentSecret)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("push snapshot failed: %s: %s", resp.Status, b)
	}
	return nil
}
