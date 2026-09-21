package adcorefake

import (
	"context"
	"fmt"

	"github.com/nemethhh/go-adcore"
)

type fakeServiceAccount struct{ s *store }

var _ adcore.ServiceAccountDirectory = (*fakeServiceAccount)(nil)

// defaultManagedPasswordInterval is what New-ADServiceAccount writes when the
// caller names no interval, and what a raw LDAP create must write too: the
// attribute is the gMSA class's only mandatory one.
const defaultManagedPasswordInterval = 30

func (f *fakeServiceAccount) Create(ctx context.Context, spec adcore.GMSASpec) (*adcore.GMSA, error) {
	const op = "ServiceAccount.Create"
	if err := spec.Validate(op, true); err != nil {
		return nil, err
	}

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	dn := "CN=" + adcore.EscapeValue(spec.Name) + "," + spec.Container
	for have := range f.s.byDN {
		if eqDN(have, dn) {
			return nil, exists(op, dn)
		}
	}
	principals, err := f.s.resolvePrincipalsLocked(op, spec.PrincipalsAllowed)
	if err != nil {
		return nil, err
	}

	o := &object{guid: f.s.nextGUID(), dn: dn, class: "gmsa"}
	o.gmsa = adcore.GMSA{
		GUID: o.guid, DN: dn, Name: spec.Name,
		SamAccountName: spec.SamAccountName, Container: spec.Container,
		Enabled: true,
		SID:     "S-1-5-21-0-0-0-" + fmt.Sprint(f.s.seq),
	}
	applyGMSASpec(&o.gmsa, spec)
	o.gmsa.PrincipalsAllowed = principals
	// Create-only: the interval is settable here and nowhere else, because
	// Active Directory refuses a modify of msDS-ManagedPasswordInterval. It is
	// also mandatory on the class, so a caller that names none gets AD's own
	// default rather than a zero the real backends never report.
	o.gmsa.ManagedPasswordIntervalInDays = defaultManagedPasswordInterval
	if spec.ManagedPasswordIntervalInDays != nil {
		o.gmsa.ManagedPasswordIntervalInDays = *spec.ManagedPasswordIntervalInDays
	}
	f.s.byDN[dn] = o

	m := o.gmsa
	return &m, nil
}

// applyGMSASpec moves every mutable field the spec names onto the model.
// ManagedPasswordIntervalInDays is deliberately absent: it is create-only.
func applyGMSASpec(g *adcore.GMSA, spec adcore.GMSASpec) {
	for _, f := range []struct {
		dst *string
		src *string
	}{
		{&g.DNSHostName, spec.DNSHostName},
		{&g.Description, spec.Description},
		{&g.DisplayName, spec.DisplayName},
	} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
	if spec.Enabled != nil {
		g.Enabled = *spec.Enabled
	}
	if spec.TrustedForDelegation != nil {
		g.TrustedForDelegation = *spec.TrustedForDelegation
	}
	if spec.ServicePrincipalNames != nil {
		g.ServicePrincipalNames = append([]string(nil), *spec.ServicePrincipalNames...)
	}
	if spec.KerberosEncryptionType != nil {
		g.KerberosEncryptionType = append([]string(nil), *spec.KerberosEncryptionType...)
	}
	switch {
	case spec.AccountExpiration.IsSet():
		t := spec.AccountExpiration.Value()
		g.AccountExpiration = &t
	case spec.AccountExpiration.IsClear():
		g.AccountExpiration = nil
	}
}

func (f *fakeServiceAccount) Get(ctx context.Context, id adcore.Identity) (*adcore.GMSA, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	o := f.s.findLocked(id)
	if o == nil || o.class != "gmsa" {
		return nil, notFound("ServiceAccount.Get", id)
	}
	m := o.gmsa
	return &m, nil
}

func (f *fakeServiceAccount) Search(ctx context.Context, q adcore.Query) ([]adcore.GMSA, error) {
	const op = "ServiceAccount.Search"
	q = q.WithDefaults(f.s.dnc)

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	var out []adcore.GMSA
	for dn, o := range f.s.byDN {
		if o.class != "gmsa" || !inScope(dn, q) {
			continue
		}
		out = append(out, o.gmsa)
	}
	if len(out) > q.SizeLimit {
		return nil, tooMany(op, q.SizeLimit)
	}
	return out, nil
}

func (f *fakeServiceAccount) Update(ctx context.Context, id adcore.Identity, spec adcore.GMSASpec) (*adcore.GMSA, error) {
	const op = "ServiceAccount.Update"
	if err := spec.Validate(op, false); err != nil {
		return nil, err
	}

	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil || o.class != "gmsa" {
		return nil, notFound(op, id)
	}
	if spec.PrincipalsAllowed != nil {
		principals, err := f.s.resolvePrincipalsLocked(op, spec.PrincipalsAllowed)
		if err != nil {
			return nil, err
		}
		o.gmsa.PrincipalsAllowed = principals
	}
	if spec.SamAccountName != "" {
		o.gmsa.SamAccountName = spec.SamAccountName
	}
	applyGMSASpec(&o.gmsa, spec)

	if spec.Name != o.gmsa.Name || !eqDN(spec.Container, o.gmsa.Container) {
		newDN := "CN=" + adcore.EscapeValue(spec.Name) + "," + spec.Container
		f.s.moveLocked(o, newDN)
		o.gmsa.DN, o.gmsa.Name, o.gmsa.Container = newDN, spec.Name, spec.Container
	}

	m := o.gmsa
	return &m, nil
}

func (f *fakeServiceAccount) Delete(ctx context.Context, id adcore.Identity) error {
	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil || o.class != "gmsa" {
		return nil
	}
	delete(f.s.byDN, o.dn)
	return nil
}
