package adcore_test

import (
	"slices"
	"testing"

	"github.com/nemethhh/go-adcore"
)

// sameSpec compares two ACESpecs. ACESpec does not embed an ACE, and its
// Rights field is a slice, so it is not comparable with ==.
func sameSpec(a, b adcore.ACESpec) bool {
	return slices.Equal(a.Rights, b.Rights) &&
		a.ObjectType == b.ObjectType &&
		a.Scope == b.Scope &&
		a.ObjectClass == b.ObjectClass &&
		a.Type == b.Type
}

// Template is a pure function: it expands a curated task into the ACEs that
// implement it, with no I/O. Two calls must agree exactly.
func TestTemplateIsPureAndStable(t *testing.T) {
	var d adcore.Delegation
	for _, task := range adcore.Tasks() {
		first, err := d.Template(task)
		if err != nil {
			t.Fatalf("Template(%q): %v", task, err)
		}
		if len(first) == 0 {
			t.Errorf("Template(%q) expanded to no ACEs", task)
		}
		second, err := d.Template(task)
		if err != nil {
			t.Fatalf("Template(%q) second call: %v", task, err)
		}
		if len(first) != len(second) {
			t.Fatalf("Template(%q) is not stable: %d then %d ACEs", task, len(first), len(second))
		}
		for i := range first {
			if !sameSpec(first[i], second[i]) {
				t.Fatalf("Template(%q) ACE %d differs between calls: %+v vs %+v", task, i, first[i], second[i])
			}
		}
	}
}

func TestTemplateRejectsUnknownTask(t *testing.T) {
	var d adcore.Delegation
	if _, err := d.Template(adcore.DelegationTask("no-such-task")); err == nil {
		t.Fatal("an unknown task must be an error, not an empty expansion")
	}
}

// CanonicalACEKey is order-insensitive over Rights and case-insensitive
// throughout: it is what drift detection and revoke-by-identity compare on, so
// two spellings of one grant must key identically.
func TestCanonicalACEKeyIgnoresOrderAndCase(t *testing.T) {
	a := adcore.ACE{Trustee: "S-1-5-21-1", Type: adcore.ACEAllow, Rights: []adcore.Right{"ReadProperty", "WriteProperty"}}
	b := adcore.ACE{Trustee: "s-1-5-21-1", Type: adcore.ACEAllow, Rights: []adcore.Right{"writeproperty", "readproperty"}}
	if adcore.CanonicalACEKey(a) != adcore.CanonicalACEKey(b) {
		t.Errorf("two spellings of one grant keyed differently:\n%q\n%q",
			adcore.CanonicalACEKey(a), adcore.CanonicalACEKey(b))
	}
}
