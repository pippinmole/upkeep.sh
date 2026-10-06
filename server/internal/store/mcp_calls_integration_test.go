package store

// MCP call log retention (migration 0026, PruneAlerting). Skipped unless
// SW_TEST_DATABASE_URL is set; see inventory_integration_test.go.

import (
	"context"
	"testing"
	"time"
)

func TestPruneAlertingMCPCalls(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	const age = 90 * 24 * time.Hour

	var userID string
	if err := f.s.Pool.QueryRow(ctx, `INSERT INTO users (email, name) VALUES ($1, 'MCP') RETURNING id`,
		f.tag+"-mcp@test.invalid").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	// Registered after the fixture's cleanup, so it runs first (LIFO).
	t.Cleanup(func() {
		_, _ = f.s.Pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})
	insert := func(tool string, createdAt time.Time) {
		t.Helper()
		if _, err := f.s.Pool.Exec(ctx, `
			INSERT INTO mcp_calls (workspace_id, created_at, user_id, credential_kind, client_name,
			                       tool, duration_ms)
			VALUES ($1, $2, $3, 'oauth', 'Claude Code', $4, 12)`,
			f.workspaceID, createdAt, userID, tool); err != nil {
			t.Fatal(err)
		}
	}
	insert("old", now.Add(-age-time.Hour))
	insert("just-old", now.Add(-age-time.Second))
	insert("boundary", now.Add(-age))
	insert("recent", now.Add(-time.Hour))

	res, err := f.s.PruneAlerting(ctx, now, 30*24*time.Hour, 90*24*time.Hour, 365*24*time.Hour, age)
	if err != nil {
		t.Fatal(err)
	}
	// Other workspaces' rows may be pruned too (the job is fleet-wide), so
	// only a lower bound holds for the count.
	if res.MCPCalls < 2 {
		t.Errorf("MCPCalls = %d, want at least 2", res.MCPCalls)
	}

	rows, err := f.s.Pool.Query(ctx,
		`SELECT tool FROM mcp_calls WHERE workspace_id = $1 ORDER BY created_at`, f.workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for rows.Next() {
		var tool string
		if err := rows.Scan(&tool); err != nil {
			t.Fatal(err)
		}
		kept = append(kept, tool)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(kept) != 2 || kept[0] != "boundary" || kept[1] != "recent" {
		t.Errorf("kept %v, want [boundary recent]", kept)
	}
}
