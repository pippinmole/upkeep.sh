package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Condition is alert_rules.condition: a property, an operator and the
// operator's value, plus the property's options. After Validate, Value is
// the canonical JSON of the typed value (nil for ValueNone) and Options
// holds every option of the property (defaults filled in).
type Condition struct {
	Property string            `json:"property"`
	Operator string            `json:"operator"`
	Value    json.RawMessage   `json:"value,omitempty"`
	Options  map[string]string `json:"options,omitempty"`
}

// ConditionError is a validation failure of one part of a condition:
// Field is "property", "operator", "value" or "options.<key>".
type ConditionError struct {
	Field, Msg string
}

func (e *ConditionError) Error() string { return e.Field + ": " + e.Msg }

func condErr(field, format string, args ...any) error {
	return &ConditionError{Field: field, Msg: fmt.Sprintf(format, args...)}
}

// ParseCondition decodes and validates stored or submitted condition JSON.
func ParseCondition(raw []byte) (Condition, error) {
	var c Condition
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Condition{}, condErr("property", "invalid condition JSON: %v", err)
	}
	return Validate(c)
}

// Validate checks c against the catalog and returns its normalised form:
// lists de-duplicated and sorted (strings trimmed, lower-cased where the
// value says so), option defaults filled in, a ValueNone value dropped.
// web/src/lib/alert-conditions.ts implements the same rules;
// alert-conditions.vectors.json keeps the two in step.
func Validate(c Condition) (Condition, error) {
	p, ok := PropertyByKey(c.Property)
	if !ok {
		return Condition{}, condErr("property", "unknown property %q", c.Property)
	}
	op, ok := p.operator(c.Operator)
	if !ok {
		return Condition{}, condErr("operator", "%s has no operator %q", p.Label, c.Operator)
	}
	out := Condition{Property: p.Key, Operator: op.Key}
	v, err := normalizeValue(op.Value, c.Value)
	if err != nil {
		return Condition{}, err
	}
	out.Value = v

	for k := range c.Options {
		if !slices.ContainsFunc(p.Options, func(o OptionSpec) bool { return o.Key == k }) {
			return Condition{}, condErr("options."+k, "%s has no option %q", p.Label, k)
		}
	}
	if len(p.Options) > 0 {
		out.Options = make(map[string]string, len(p.Options))
		for _, o := range p.Options {
			val, set := c.Options[o.Key]
			if !set || val == "" {
				val = o.Default
			}
			if !slices.ContainsFunc(o.Choices, func(ch Choice) bool { return ch.Value == val }) {
				return Condition{}, condErr("options."+o.Key, "invalid %s %q", strings.ToLower(o.Label), val)
			}
			out.Options[o.Key] = val
		}
	}
	return out, nil
}

func isNull(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || bytes.Equal(t, []byte("null"))
}

func normalizeValue(spec ValueSpec, raw json.RawMessage) (json.RawMessage, error) {
	switch spec.Kind {
	case ValueNone:
		if !isNull(raw) {
			return nil, condErr("value", "this operator takes no value")
		}
		return nil, nil
	case ValueInts:
		var nums []float64
		if isNull(raw) || json.Unmarshal(raw, &nums) != nil {
			return nil, condErr("value", "enter a list of numbers")
		}
		var out []int
		for _, n := range nums {
			if n != math.Trunc(n) || n < float64(spec.Min) || n > float64(spec.Max) {
				return nil, condErr("value", "%v is not a whole number from %d to %d", n, spec.Min, spec.Max)
			}
			if !slices.Contains(out, int(n)) {
				out = append(out, int(n))
			}
		}
		if len(out) == 0 {
			return nil, condErr("value", "enter at least one")
		}
		if spec.MaxItems > 0 && len(out) > spec.MaxItems {
			return nil, condErr("value", "at most %d", spec.MaxItems)
		}
		slices.Sort(out)
		return mustJSON(out), nil
	case ValueStrings:
		var items []string
		if isNull(raw) || json.Unmarshal(raw, &items) != nil {
			return nil, condErr("value", "enter a list of names")
		}
		var re *regexp.Regexp
		if spec.Pattern != "" {
			re = compiled(spec.Pattern)
		}
		var out []string
		for _, s := range items {
			s = strings.TrimSpace(s)
			if spec.Lower {
				s = strings.ToLower(s)
			}
			if s == "" || slices.Contains(out, s) {
				continue
			}
			if spec.MaxLength > 0 && len([]rune(s)) > spec.MaxLength {
				return nil, condErr("value", "%q is longer than %d characters", s, spec.MaxLength)
			}
			if re != nil && !re.MatchString(s) {
				return nil, condErr("value", "%q is not a valid name", s)
			}
			out = append(out, s)
		}
		if len(out) == 0 {
			return nil, condErr("value", "enter at least one")
		}
		if spec.MaxItems > 0 && len(out) > spec.MaxItems {
			return nil, condErr("value", "at most %d", spec.MaxItems)
		}
		slices.Sort(out)
		return mustJSON(out), nil
	case ValueEnum:
		var s string
		if isNull(raw) || json.Unmarshal(raw, &s) != nil ||
			!slices.ContainsFunc(spec.Choices, func(c Choice) bool { return c.Value == s }) {
			return nil, condErr("value", "choose one of the listed values")
		}
		return mustJSON(s), nil
	case ValueInt:
		var n float64
		if isNull(raw) || json.Unmarshal(raw, &n) != nil || n != math.Trunc(n) ||
			n < float64(spec.Min) || n > float64(spec.Max) {
			return nil, condErr("value", "enter a whole number from %d to %d", spec.Min, spec.Max)
		}
		return mustJSON(int(n)), nil
	}
	return nil, condErr("value", "unsupported value kind %q", spec.Kind)
}

var (
	reMu    sync.Mutex
	reCache = map[string]*regexp.Regexp{}
)

func compiled(p string) *regexp.Regexp {
	reMu.Lock()
	defer reMu.Unlock()
	re, ok := reCache[p]
	if !ok {
		re = regexp.MustCompile(p)
		reCache[p] = re
	}
	return re
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// Accessors for a validated condition's value.

// Ints is the value of an int_list operator.
func (c Condition) Ints() []int {
	var out []int
	_ = json.Unmarshal(c.Value, &out)
	return out
}

// Strings is the value of a string_list operator.
func (c Condition) Strings() []string {
	var out []string
	_ = json.Unmarshal(c.Value, &out)
	return out
}

// Enum is the value of an enum operator.
func (c Condition) Enum() string {
	var s string
	_ = json.Unmarshal(c.Value, &s)
	return s
}

// Int is the value of an int operator.
func (c Condition) Int() int {
	var n int
	_ = json.Unmarshal(c.Value, &n)
	return n
}

// JSON is the condition's canonical JSON.
func (c Condition) JSON() []byte { return mustJSON(c) }

// SameCondition reports whether two condition JSON documents are equal as
// JSON values (stored jsonb comes back reformatted).
func SameCondition(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return jsonEqual(x, y)
}

func jsonEqual(a, b any) bool {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, v := range av {
			w, ok := bv[k]
			if !ok || !jsonEqual(v, w) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !jsonEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}
