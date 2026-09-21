package adcore_test

import (
	"errors"
	"testing"

	"github.com/nemethhh/go-adcore"
)

func TestValidateNameRejectsEmpty(t *testing.T) {
	if err := adcore.ValidateName("OU.Create", ""); err == nil {
		t.Fatal("an empty name must be rejected")
	}
}

func TestValidateContainerRejectsNonDN(t *testing.T) {
	if err := adcore.ValidateContainer("OU.Create", "not a dn"); err == nil {
		t.Fatal("a container that is not a DN must be rejected")
	}
	if err := adcore.ValidateContainer("OU.Create", "DC=corp,DC=local"); err != nil {
		t.Fatalf("a valid DN was rejected: %v", err)
	}
}

// Delete returns nil only after a re-read confirms the object is gone. A
// Remove-AD* (or an LDAP Del) that reports success while the deletion was
// refused is an error, not a success.
func TestConfirmAbsent(t *testing.T) {
	id := adcore.ByGUID("f1e2")

	if err := (adcore.PresenceCheck{Present: false}).ConfirmAbsent("OU.Delete", id, "OU=Sales,DC=corp,DC=local"); err != nil {
		t.Fatalf("an absent object must confirm: %v", err)
	}

	err := (adcore.PresenceCheck{Present: true}).ConfirmAbsent("OU.Delete", id, "OU=Sales,DC=corp,DC=local")
	if err == nil {
		t.Fatal("an object still present after Delete must be an error")
	}
	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindConstraint {
		t.Fatalf("want a KindConstraint adcore.Error, got %#v", err)
	}
}

// A probe that failed for a reason other than "not found" has not verified
// anything. Treating a server-down as a successful delete drops the resource
// from state while the object lives on, unmanaged.
func TestConfirmAbsentRejectsAnUnverifiedProbe(t *testing.T) {
	err := adcore.PresenceCheck{
		Present:       false,
		Kind:          adcore.KindTransient,
		ExceptionType: "ADServerDownException",
	}.ConfirmAbsent("OU.Delete", adcore.ByGUID("f1e2"), "OU=Sales,DC=corp,DC=local")

	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindTransient {
		t.Fatalf("want a KindTransient adcore.Error, got %#v", err)
	}
}

func TestWithIdentityDecorates(t *testing.T) {
	base := error(&adcore.Error{Kind: adcore.KindNotFound, Op: "OU.Get"})
	got := adcore.WithIdentity(base, "OU.Get", adcore.ByGUID("f1e2"))
	var e *adcore.Error
	if !errors.As(got, &e) {
		t.Fatalf("want an adcore.Error, got %#v", got)
	}
	if e.Identity != "guid:f1e2" {
		t.Errorf("Identity = %q, want %q", e.Identity, "guid:f1e2")
	}
}
