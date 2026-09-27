package notify

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

type fake struct{ typ string }

func (f fake) Spec() Spec {
	return Spec{Type: f.typ, Label: f.typ, Fields: []Field{
		{Key: "to", Label: "To", Type: FieldText, Required: true, MaxLength: 5},
		{Key: "mode", Label: "Mode", Type: FieldSelect, Options: []Option{{"a", "A"}, {"b", "B"}}},
	}}
}
func (f fake) Validate(cfg Config) error { return ValidateRequired(f.Spec(), cfg) }
func (f fake) Send(context.Context, Config, Notification) (Result, error) {
	return Result{StatusCode: 200}, nil
}

func TestRegistry(t *testing.T) {
	r := NewRegistry(fake{"zeta"}, fake{"alpha"})
	if n, ok := r.Get("alpha"); !ok || n.Spec().Type != "alpha" {
		t.Fatal("alpha not registered")
	}
	if _, ok := r.Get("missing"); ok {
		t.Fatal("unexpected type")
	}
	specs := r.Specs()
	if len(specs) != 2 || specs[0].Type != "alpha" || specs[1].Type != "zeta" {
		t.Fatalf("specs not sorted: %+v", specs)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate registration did not panic")
		}
	}()
	r.Register(fake{"alpha"})
}

func TestValidateRequired(t *testing.T) {
	f := fake{"x"}
	if err := f.Validate(Config{"to": "me", "mode": "a"}); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []Config{{}, {"to": "toolong"}, {"to": "me", "mode": "c"}} {
		if f.Validate(cfg) == nil {
			t.Errorf("%v: valid", cfg)
		}
	}
}

func TestPermanent(t *testing.T) {
	base := errors.New("boom")
	if IsPermanent(base) || Permanent(nil) != nil {
		t.Fatal("plain error is permanent")
	}
	wrapped := fmt.Errorf("send: %w", Permanent(base))
	if !IsPermanent(wrapped) || !errors.Is(wrapped, base) {
		t.Fatal("Permanent lost through wrapping")
	}
}
