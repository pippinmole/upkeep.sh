package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pippinmole/upkeep.sh/agent/internal/transport"
)

type storedCredentials struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
}

// loadOrEnroll returns existing credentials from disk, or performs
// one-time enrollment using SW_ENROLLMENT_TOKEN and persists the result.
func loadOrEnroll(client *transport.Client, credPath string) (agentID, agentSecret string, err error) {
	if b, err := os.ReadFile(credPath); err == nil {
		var creds storedCredentials
		if err := json.Unmarshal(b, &creds); err == nil && creds.AgentID != "" {
			return creds.AgentID, creds.AgentSecret, nil
		}
	}

	token := os.Getenv("SW_ENROLLMENT_TOKEN")
	if token == "" {
		return "", "", fmt.Errorf("no stored credentials at %s and SW_ENROLLMENT_TOKEN not set", credPath)
	}
	hostname, _ := os.Hostname()

	resp, err := client.Enroll(token, hostname)
	if err != nil {
		return "", "", err
	}

	if err := os.MkdirAll(dirOf(credPath), 0o700); err != nil {
		return "", "", err
	}
	b, _ := json.Marshal(storedCredentials{AgentID: resp.AgentID, AgentSecret: resp.AgentSecret})
	if err := os.WriteFile(credPath, b, 0o600); err != nil {
		return "", "", err
	}
	return resp.AgentID, resp.AgentSecret, nil
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
