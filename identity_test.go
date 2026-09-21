package adcore_test

import (
	"testing"

	"github.com/nemethhh/go-adcore"
)

func TestIdentityAccessors(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   adcore.Identity
		form string
		arg  string
		str  string
	}{
		{"guid", adcore.ByGUID("f1e2"), "guid", "f1e2", "guid:f1e2"},
		{"dn", adcore.ByDN("OU=Sales,DC=corp,DC=local"), "dn", "OU=Sales,DC=corp,DC=local", "dn:OU=Sales,DC=corp,DC=local"},
		{"sid", adcore.BySID("S-1-5-21-1"), "sid", "S-1-5-21-1", "sid:S-1-5-21-1"},
		{"sam", adcore.BySAM("jdoe"), "sam", "jdoe", "sam:jdoe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := adcore.IdentityForm(tc.id); got != tc.form {
				t.Errorf("IdentityForm = %q, want %q", got, tc.form)
			}
			if got := adcore.IdentityArg(tc.id); got != tc.arg {
				t.Errorf("IdentityArg = %q, want %q", got, tc.arg)
			}
			if got := tc.id.String(); got != tc.str {
				t.Errorf("String = %q, want %q", got, tc.str)
			}
		})
	}
}
