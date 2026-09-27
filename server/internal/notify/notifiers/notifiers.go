// Package notifiers assembles the registry of every channel type the
// server can deliver to. Adding a channel type = one line here (see the
// internal/notify package doc for the full recipe).
package notifiers

import (
	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/notify"
	"github.com/pippinmole/upkeep.sh/server/internal/notify/webhook"
)

// Registry returns every supported channel type, all making outbound
// requests through g.
func Registry(g *netguard.Guard) *notify.Registry {
	return notify.NewRegistry(
		webhook.New(g),
		// email.New(...), slack.New(g), discord.New(g), ntfy.New(g): TASKS.md follow-ups.
	)
}
