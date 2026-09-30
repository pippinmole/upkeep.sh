package alerting

// The property catalogue: every host property a rule condition can test,
// its operators, the value each operator takes and its options
// (docs/ALERTING.md "MVP property catalogue"). The dashboard renders the
// rule form from the same declaration: `go test ./internal/alerting
// -update` writes web/src/lib/alert-properties.json (golden test).
//
// Adding a property: declare it here, add its evaluator in
// store/alertrules_eval.go (TestEveryPropertyHasAnEvaluator in the store
// package fails otherwise), regenerate the JSON and add vectors to
// web/src/lib/alert-conditions.vectors.json.

// ValueKind is the type of a condition's value.
type ValueKind string

const (
	ValueNone    ValueKind = "none"        // no value
	ValueInts    ValueKind = "int_list"    // list of integers in [Min, Max]
	ValueStrings ValueKind = "string_list" // list of strings
	ValueEnum    ValueKind = "enum"        // one of Choices
	ValueInt     ValueKind = "int"         // one integer in [Min, Max]
)

// Choice is one allowed value of an enum value or an option.
type Choice struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// ValueSpec declares an operator's value.
type ValueSpec struct {
	Kind        ValueKind `json:"kind"`
	Label       string    `json:"label,omitempty"`
	Placeholder string    `json:"placeholder,omitempty"`
	Help        string    `json:"help,omitempty"`
	// int_list items / int: inclusive range.
	Min int `json:"min,omitempty"`
	Max int `json:"max,omitempty"`
	// int_list / string_list: at most this many items (after de-duplication).
	MaxItems int `json:"maxItems,omitempty"`
	// string_list: per-item length limit, an optional pattern every item
	// must match (RE2 and JavaScript compatible), and whether items are
	// lower-cased before validation.
	MaxLength int    `json:"maxLength,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
	Lower     bool   `json:"lower,omitempty"`
	// enum
	Choices []Choice `json:"choices,omitempty"`
	// int: display unit ("minutes").
	Unit string `json:"unit,omitempty"`
}

// Operator is one way of testing a property.
type Operator struct {
	Key   string    `json:"key"`
	Label string    `json:"label"`
	Value ValueSpec `json:"value"`
}

// OptionSpec is a property qualifier (a select with a default).
type OptionSpec struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Help    string   `json:"help,omitempty"`
	Default string   `json:"default"`
	Choices []Choice `json:"choices"`
}

// Property is one testable host property.
type Property struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
	// Subject names what one alert is about ("port", "package", ...); ""
	// = one alert per host.
	Subject   string       `json:"subject,omitempty"`
	Operators []Operator   `json:"operators"`
	Options   []OptionSpec `json:"options,omitempty"`
}

// Property keys.
const (
	PropListeningPort    = "listening_port"
	PropPackageInstalled = "package_installed"
	PropOS               = "os"
	PropRebootRequired   = "reboot_required"
	PropVulnerability    = "vulnerability"
	PropHostNotSeen      = "host_not_seen"
	PropCollectorFailed  = "collector_failed"
)

// Bind options of listening_port.
const (
	BindNonLoopback   = "non_loopback"
	BindAllInterfaces = "all_interfaces"
	BindLoopback      = "loopback"
	BindAny           = "any"
)

// SeverityRanks maps the vulnerability severities a rule can name to
// findings.severity_rank (1 negligible, 2 low, 3 unknown, 4 medium,
// 5 high, 6 critical). "At least low" includes unknown.
var SeverityRanks = map[string]int{"low": 2, "medium": 4, "high": 5, "critical": 6}

var portList = ValueSpec{
	Kind: ValueInts, Label: "Ports", Placeholder: "22, 3389", Min: 1, Max: 65535, MaxItems: 50,
}

var (
	anyOf  = "is one of"
	noneOf = "is not one of"
)

// Catalog lists the properties in display order.
var Catalog = []Property{
	{
		Key: PropListeningPort, Label: "Listening port", Subject: "port",
		Description: "A port a process on the host listens on. One alert per port and protocol.",
		Operators: []Operator{
			{Key: "in", Label: anyOf, Value: portList},
			{Key: "not_in", Label: noneOf, Value: withHelp(portList,
				"An allowlist: fires for every listening port that is not in it.")},
		},
		Options: []OptionSpec{
			{Key: "protocol", Label: "Protocol", Default: "tcp", Choices: []Choice{
				{"tcp", "TCP"}, {"udp", "UDP"}, {"any", "TCP or UDP"}}},
			{Key: "bind", Label: "Bound to", Default: BindNonLoopback,
				Help: "Which listening addresses count.",
				Choices: []Choice{
					{BindNonLoopback, "Any address except loopback"},
					{BindAllInterfaces, "All interfaces (0.0.0.0 or ::)"},
					{BindLoopback, "Loopback only (127.0.0.0/8, ::1)"},
					{BindAny, "Any address"},
				}},
		},
	},
	{
		Key: PropPackageInstalled, Label: "Package", Subject: "package",
		Description: "An installed package, by name, from any package source the agent collects.",
		Operators: []Operator{
			{Key: "installed", Label: "is installed", Value: packageNames},
			{Key: "not_installed", Label: "is not installed", Value: withHelp(packageNames,
				"Fires for every listed package missing from a host whose package inventory is known.")},
		},
	},
	{
		Key: PropOS, Label: "Operating system",
		Description: "The host's OS id (ubuntu, debian, alpine, …) or family (linux, windows, macos).",
		Operators: []Operator{
			{Key: "in", Label: anyOf, Value: osNames},
			{Key: "not_in", Label: noneOf, Value: osNames},
		},
	},
	{
		Key: PropRebootRequired, Label: "Reboot required",
		Description: "The host reports that it needs a reboot (for example after a kernel update).",
		Operators:   []Operator{{Key: "is_true", Label: "is required", Value: ValueSpec{Kind: ValueNone}}},
	},
	{
		Key: PropVulnerability, Label: "Vulnerability", Subject: "finding",
		Description: "An open vulnerability finding on the host. One alert per finding.",
		Operators: []Operator{
			{Key: "severity_at_least", Label: "severity is at least", Value: ValueSpec{
				Kind: ValueEnum, Label: "Severity", Choices: []Choice{
					{"low", "Low"}, {"medium", "Medium"}, {"high", "High"}, {"critical", "Critical"}}}},
			{Key: "kev", Label: "is known exploited (CISA KEV)", Value: ValueSpec{Kind: ValueNone}},
		},
		Options: []OptionSpec{
			{Key: "source", Label: "Found in", Default: "any", Choices: []Choice{
				{"any", "Host packages and container images"},
				{"packages", "Host packages"},
				{"images", "Container images"},
			}},
		},
	},
	{
		Key: PropHostNotSeen, Label: "Host not seen",
		Description: "No snapshot has arrived for the host for a while.",
		Operators: []Operator{{Key: "for_more_than", Label: "for more than", Value: ValueSpec{
			Kind: ValueInt, Label: "Minutes", Min: 5, Max: 43200, Unit: "minutes", Placeholder: "30"}}},
	},
	{
		Key: PropCollectorFailed, Label: "Collector failed", Subject: "collector",
		Description: "A collector reported an error in the host's latest snapshot. One alert per collector.",
		Operators: []Operator{
			{Key: "any", Label: "any collector", Value: ValueSpec{Kind: ValueNone}},
			{Key: "in", Label: anyOf, Value: ValueSpec{
				Kind: ValueStrings, Label: "Collectors", Placeholder: "deb_packages, tcp_listeners",
				MaxItems: 30, MaxLength: 64, Pattern: `^[a-z0-9_]+$`, Lower: true}},
		},
	},
}

var packageNames = ValueSpec{
	Kind: ValueStrings, Label: "Package names", Placeholder: "telnetd, rsh-server",
	Help:     "Exact names, case-insensitive.",
	MaxItems: 50, MaxLength: 200, Pattern: `^[^,]+$`, Lower: true,
}

var osNames = ValueSpec{
	Kind: ValueStrings, Label: "OS ids or families", Placeholder: "ubuntu, debian, windows",
	MaxItems: 20, MaxLength: 64, Pattern: `^[a-z0-9._-]+$`, Lower: true,
}

func withHelp(v ValueSpec, help string) ValueSpec {
	v.Help = help
	return v
}

// PropertyByKey returns a catalogue entry.
func PropertyByKey(key string) (Property, bool) {
	for _, p := range Catalog {
		if p.Key == key {
			return p, true
		}
	}
	return Property{}, false
}

func (p Property) operator(key string) (Operator, bool) {
	for _, o := range p.Operators {
		if o.Key == key {
			return o, true
		}
	}
	return Operator{}, false
}
