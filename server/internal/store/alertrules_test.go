package store

import (
	"testing"

	"github.com/pippinmole/upkeep.sh/server/internal/alerting"
)

// Adding a property to the catalogue needs an evaluator here (and the
// other way round).
func TestEveryPropertyHasAnEvaluator(t *testing.T) {
	for _, p := range alerting.Catalog {
		if propertyEvaluators[p.Key] == nil {
			t.Errorf("property %q has no evaluator", p.Key)
		}
	}
	if len(propertyEvaluators) != len(alerting.Catalog) {
		t.Errorf("%d evaluators for %d properties", len(propertyEvaluators), len(alerting.Catalog))
	}
}
