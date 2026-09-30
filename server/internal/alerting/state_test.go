package alerting

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestDiff(t *testing.T) {
	cond := []byte(`{"property":"listening_port","operator":"in","value":[22],"options":{"bind":"non_loopback","protocol":"tcp"}}`)
	// The same condition as Postgres returns it (jsonb reorders keys).
	stored := json.RawMessage(`{"value": [22], "options": {"bind": "non_loopback", "protocol": "tcp"}, "operator": "in", "property": "listening_port"}`)
	edited := json.RawMessage(`{"property":"listening_port","operator":"in","value":[2222],"options":{"bind":"non_loopback","protocol":"tcp"}}`)
	det := json.RawMessage(`{"addresses":["0.0.0.0"]}`)
	m := func(host, subject string) Match {
		return Match{HostID: host, Subject: subject, Title: "Port 22/tcp is listening", Details: det}
	}
	f := func(id, host, subject string, c json.RawMessage) Firing {
		return Firing{ID: id, HostID: host, Subject: subject, Condition: c, Title: "Port 22/tcp is listening",
			Details: json.RawMessage(`{"addresses": ["0.0.0.0"]}`)}
	}
	hosts := map[string]HostStatus{
		"h1": HostOK, "h2": HostOK, "h3": HostOK,
		"archived": ReasonHostArchived, "outside": ReasonOutOfScope,
	}

	firing := []Firing{
		f("keep", "h1", "tcp/22", stored),           // still matches, unchanged
		f("clear", "h2", "tcp/22", stored),          // no longer matches
		f("changed", "h3", "tcp/22", edited),        // no longer matches, condition edited since
		f("arch", "archived", "tcp/22", stored),     // host archived
		f("scope", "outside", "tcp/22", stored),     // host left the rule's scope
		f("gone", "deleted-host", "tcp/22", stored), // host not listed at all
		f("unknown", "h-unknown", "tcp/22", stored), // evaluator couldn't read the host
		f("refresh", "h1", "udp/22", stored),        // matches with new details
		f("recond", "h3", "tcp/2222", edited),       // still matches after the edit
	}
	hosts["h-unknown"] = HostOK
	refreshed := m("h1", "udp/22")
	refreshed.Details = json.RawMessage(`{"addresses":["0.0.0.0","::"]}`)
	res := Result{
		Matches: []Match{
			m("h1", "tcp/22"), refreshed, m("h3", "tcp/2222"),
			m("h2", "tcp/80"), m("h2", "tcp/80"), // new, duplicated: fires once
			m("archived", "tcp/443"), // archived hosts never fire
			m("nobody", "tcp/22"),    // not a host of this evaluation
		},
		Unknown: map[string]bool{"h-unknown": true},
	}
	// "recond" matches but was recorded under the old condition: refreshed
	// so a later clear isn't mistaken for an edit.
	p := Diff(firing, res, hosts, cond)

	if !reflect.DeepEqual(p.Keep, []string{"keep"}) {
		t.Errorf("keep: %v", p.Keep)
	}
	wantResolve := []Resolution{
		{"clear", ReasonCleared}, {"changed", ReasonRuleChanged}, {"arch", ReasonHostArchived},
		{"scope", ReasonOutOfScope}, {"gone", ReasonOutOfScope},
	}
	if !reflect.DeepEqual(p.Resolve, wantResolve) {
		t.Errorf("resolve: %v", p.Resolve)
	}
	if len(p.Refresh) != 2 || p.Refresh[0].ID != "refresh" || p.Refresh[1].ID != "recond" {
		t.Errorf("refresh: %+v", p.Refresh)
	}
	if len(p.Fire) != 1 || p.Fire[0].Key() != [2]string{"h2", "tcp/80"} {
		t.Errorf("fire: %+v", p.Fire)
	}
}

func TestDiffEmpty(t *testing.T) {
	p := Diff(nil, Result{}, nil, []byte(`{}`))
	if p.Fire != nil || p.Resolve != nil || p.Refresh != nil || p.Keep != nil {
		t.Fatalf("%+v", p)
	}
	// A host-level match (no subject) fires once per host.
	p = Diff(nil, Result{Matches: []Match{{HostID: "h", Title: "Reboot required"}}}, map[string]HostStatus{"h": HostOK}, []byte(`{}`))
	if len(p.Fire) != 1 || p.Fire[0].Subject != "" {
		t.Fatalf("%+v", p)
	}
}

func TestNotifies(t *testing.T) {
	for _, r := range []string{ReasonRuleChanged, ReasonRuleDisabled, ReasonRuleDeleted, ReasonOutOfScope, ReasonHostArchived} {
		if Notifies(r) {
			t.Errorf("%s notifies", r)
		}
	}
	if !Notifies(ReasonCleared) {
		t.Error("cleared doesn't notify")
	}
}

func TestSameCondition(t *testing.T) {
	if !SameCondition([]byte(`{"a":[1,2],"b":{"c":"d"}}`), []byte(`{"b": {"c": "d"}, "a": [1, 2]}`)) {
		t.Error("reordered keys")
	}
	for _, other := range []string{`{"a":[2,1],"b":{"c":"d"}}`, `{"a":[1,2]}`, `{"a":[1,2],"b":{"c":"e"}}`, `[]`, `x`} {
		if SameCondition([]byte(`{"a":[1,2],"b":{"c":"d"}}`), []byte(other)) {
			t.Errorf("equal to %s", other)
		}
	}
}
