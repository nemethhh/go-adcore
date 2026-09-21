package adcore_test

import (
	"testing"

	"github.com/nemethhh/go-adcore"
)

// An escaped comma is part of a component, not a separator. Splitting on bare
// commas silently mis-parses "OU=Sales\, EMEA" into two components, which
// would move an object to the wrong container.
func TestSplitDNHonoursEscapedCommas(t *testing.T) {
	got, err := adcore.SplitDN(`OU=Sales\, EMEA,DC=corp,DC=local`)
	if err != nil {
		t.Fatalf("SplitDN: %v", err)
	}
	want := []string{`OU=Sales\, EMEA`, `DC=corp`, `DC=local`}
	if len(got) != len(want) {
		t.Fatalf("SplitDN = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SplitDN = %q, want %q", got, want)
		}
	}
}

func TestContainerOf(t *testing.T) {
	got, err := adcore.ContainerOf("OU=Staff,OU=Sales,DC=corp,DC=local")
	if err != nil {
		t.Fatalf("ContainerOf: %v", err)
	}
	if want := "OU=Sales,DC=corp,DC=local"; got != want {
		t.Errorf("ContainerOf = %q, want %q", got, want)
	}
}

func TestEqualFoldDN(t *testing.T) {
	eq, err := adcore.EqualFoldDN("ou=sales,dc=corp,dc=local", "OU=Sales, DC=corp, DC=local")
	if err != nil {
		t.Fatalf("EqualFoldDN: %v", err)
	}
	if !eq {
		t.Error("DNs differing only in case and separator spacing must compare equal")
	}
}

func TestEscapeFilter(t *testing.T) {
	if got := adcore.EscapeFilter(`a*b(c)d\e`); got == `a*b(c)d\e` {
		t.Errorf("EscapeFilter left RFC 4515 metacharacters unescaped: %q", got)
	}
}
