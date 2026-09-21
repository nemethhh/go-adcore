package adcore_test

import (
	"testing"

	"github.com/nemethhh/go-adcore"
)

// TestGMSASpecValidate exercises adcore.GMSASpec.validate directly. It lives here
// (package adpwsh, white-box) because validate is unexported: an
// adpwsh_test-package test cannot reach it, unlike Create's round trip.
//
// Moved out of serviceaccount_test.go, which now holds the fake-backed
// ServiceAccountClient tests: those need transport/fake, and transport/fake
// imports the adpwsh package, so a fake-backed test cannot live in the
// internal (package adpwsh) test binary without creating an import cycle.
//
// forCreate follows GroupSpec.validate's convention (op string, forCreate
// bool): the DNSHostName-required rule gates on forCreate, never on the op
// string. An earlier version compared op == "GMSA.Create" directly, which
// silently never matched the real call site (go-adpwsh's ServiceAccountClient.Create
// passes "ServiceAccount.Create", per the <Resource>.<Verb> convention every
// other sub-client uses) — this table now also covers forCreate=false, so a
// future edit that reintroduces an op-string comparison fails loudly here
// too, not just through the client's end-to-end test.
func TestGMSASpecValidate(t *testing.T) {
	cases := []struct {
		name      string
		spec      adcore.GMSASpec
		forCreate bool
		wantErr   bool
	}{
		{"ok", adcore.GMSASpec{Name: "svc-web", SamAccountName: "svc-web", Container: "OU=x,DC=corp,DC=local", DNSHostName: adcore.String("svc-web.corp.local")}, true, false},
		{"sam 15 ok", adcore.GMSASpec{Name: "abcdefghij12345", SamAccountName: "abcdefghij12345", Container: "OU=x,DC=corp,DC=local", DNSHostName: adcore.String("h.corp.local")}, true, false},
		{"sam 16 too long", adcore.GMSASpec{Name: "abcdefghij123456", SamAccountName: "abcdefghij123456", Container: "OU=x,DC=corp,DC=local", DNSHostName: adcore.String("h.corp.local")}, true, true},
		{"no container", adcore.GMSASpec{Name: "svc", SamAccountName: "svc", DNSHostName: adcore.String("h.corp.local")}, true, true},
		{"no dnshostname, forCreate", adcore.GMSASpec{Name: "svc", SamAccountName: "svc", Container: "OU=x,DC=corp,DC=local"}, true, true},
		{"no dnshostname, not create", adcore.GMSASpec{Name: "svc", SamAccountName: "svc", Container: "OU=x,DC=corp,DC=local"}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.spec.Validate("GMSA.Create", c.forCreate)
			if (err != nil) != c.wantErr {
				t.Fatalf("validate() err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

// TestComputerSpecValidate exercises adcore.ComputerSpec.validate directly, the same
// way TestGMSASpecValidate exercises adcore.GMSASpec.validate above. The key
// divergence from gMSA: AD does not enforce the 15-char NetBIOS limit for
// computer accounts, so adcore.ComputerSpec.Validate must not cap SamAccountName's
// length. The 20-char case below is the guard for that requirement.
func TestComputerSpecValidate(t *testing.T) {
	base := adcore.ComputerSpec{Name: "WEB01", SamAccountName: "WEB01$", Container: "OU=x,DC=corp,DC=local"}
	if err := base.Validate("Computer.Create", true); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}

	if err := (adcore.ComputerSpec{SamAccountName: "WEB01$", Container: "OU=x,DC=corp,DC=local"}).Validate("Computer.Create", true); err == nil {
		t.Error("missing Name should fail")
	}
	// Length is NOT capped for computers (unlike gMSA) — AD does not enforce it.
	long := adcore.ComputerSpec{Name: "THISISATWENTYCHARNAME", SamAccountName: "THISISATWENTYCHARNAME$", Container: "OU=x,DC=corp,DC=local"}
	if err := long.Validate("Computer.Create", true); err != nil {
		t.Errorf("20-char sam must be allowed (AD permits it); got %v", err)
	}
}
