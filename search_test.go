package adcore_test

import (
	"testing"

	"github.com/nemethhh/go-adcore"
)

func TestQueryWithDefaults(t *testing.T) {
	got := adcore.Query{}.WithDefaults("DC=corp,DC=local")
	if got.SearchBase != "DC=corp,DC=local" {
		t.Errorf("SearchBase = %q, want the naming context", got.SearchBase)
	}
	if got.Scope != adcore.SearchScopeSubtree {
		t.Errorf("Scope = %q, want subtree", got.Scope)
	}
	if got.SizeLimit != adcore.DefaultSizeLimit {
		t.Errorf("SizeLimit = %d, want %d", got.SizeLimit, adcore.DefaultSizeLimit)
	}
}

func TestQueryWithDefaultsKeepsExplicitValues(t *testing.T) {
	q := adcore.Query{SearchBase: "OU=Sales,DC=corp,DC=local", Scope: adcore.SearchScopeOneLevel, SizeLimit: 5}
	got := q.WithDefaults("DC=corp,DC=local")
	if got != q {
		t.Errorf("WithDefaults overwrote explicit values: %+v", got)
	}
}
