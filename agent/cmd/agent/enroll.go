package main

import (
	"fmt"
	"os"

	"github.com/pippinmole/upkeep.sh/agent/internal/transport"
)

// loadOrEnroll returns existing credentials from disk, or performs
// one-time enrollment using SW_ENROLLMENT_TOKEN and persists the result.
func loadOrEnroll(client *transport.Client, credPath string) (storedCredentials, error) {
	if creds, ok := loadCredentials(credPath); ok {
		return creds, nil
	}

	token := os.Getenv("SW_ENROLLMENT_TOKEN")
	if token == "" {
		return storedCredentials{}, fmt.Errorf("no stored credentials at %s and SW_ENROLLMENT_TOKEN not set", credPath)
	}
	hostname, _ := os.Hostname()

	resp, err := client.Enroll(transport.EnrollRequest{
		EnrollmentToken: token, Hostname: hostname, Version: version, Platform: platform(),
	})
	if err != nil {
		return storedCredentials{}, err
	}
	creds := storedCredentials{AgentID: resp.AgentID, AgentSecret: resp.AgentSecret}
	if err := saveCredentials(credPath, creds); err != nil {
		return storedCredentials{}, err
	}
	return creds, nil
}
