package adcorefake

import (
	"context"
	"fmt"

	"github.com/nemethhh/go-adcore"
)

type fakeComputer struct{ s *store }

var _ adcore.ComputerDirectory = (*fakeComputer)(nil)

// resolvePrincipalsLocked turns the identities a spec carries into the object
// GUIDs a model carries.
//
// A principal that resolves to nothing is an error naming it, never a silently
// shorter list — the same rule both real backends follow, because a delegation
// written with a principal missing applies cleanly, does not work, and says
// nothing about why.
func (s *store) resolvePrincipalsLocked(op string, ids []adcore.Identity) ([]string, error) {
	if ids == nil {
		return nil, nil
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		o := s.findLocked(id)
		if o == nil {
			return nil, &adcore.Error{
				Kind: adcore.KindNotFound, Op: op, Identity: id.String(),
				Err: fmt.Errorf("principal %q does not exist", adcore.IdentityArg(id)),
			}
		}
		out = append(out, o.guid)
	}
	return out, nil
}

func (f *fakeComputer) Create(ctx context.Context, spec adcore.ComputerSpec) (*adcore.Computer, error) {
	const op = "Computer.Create"
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

	o := &object{guid: f.s.nextGUID(), dn: dn, class: "computer"}
	o.computer = adcore.Computer{
		GUID: o.guid, DN: dn, Name: spec.Name,
		SamAccountName: spec.SamAccountName, Container: spec.Container,
		// A computer account is created enabled; there is no password step to
		// wait for, which is what makes it differ from a user here.
		Enabled: true,
		SID:     "S-1-5-21-0-0-0-" + fmt.Sprint(f.s.seq),
	}
	applyComputerSpec(&o.computer, spec)
	o.computer.PrincipalsAllowed = principals
	f.s.byDN[dn] = o

	m := o.computer
	return &m, nil
}

// applyComputerSpec moves every field the spec names onto the model, leaving
// the rest alone. nil means "leave alone" for a pointer and for a slice
// pointer alike; an empty non-nil slice means "replace with nothing", which is
// why the two cases cannot be collapsed.
func applyComputerSpec(c *adcore.Computer, spec adcore.ComputerSpec) {
	for _, f := range []struct {
		dst *string
		src *string
	}{
		{&c.DNSHostName, spec.DNSHostName},
		{&c.Description, spec.Description},
		{&c.DisplayName, spec.DisplayName},
		{&c.Location, spec.Location},
		{&c.ManagedBy, spec.ManagedBy},
	} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
	if spec.Enabled != nil {
		c.Enabled = *spec.Enabled
	}
	if spec.TrustedForDelegation != nil {
		c.TrustedForDelegation = *spec.TrustedForDelegation
	}
	if spec.ServicePrincipalNames != nil {
		c.ServicePrincipalNames = append([]string(nil), *spec.ServicePrincipalNames...)
	}
	if spec.AllowedToDelegateTo != nil {
		c.AllowedToDelegateTo = append([]string(nil), *spec.AllowedToDelegateTo...)
	}
	if spec.KerberosEncryptionType != nil {
		c.KerberosEncryptionType = append([]string(nil), *spec.KerberosEncryptionType...)
	}
	switch {
	case spec.AccountExpiration.IsSet():
		t := spec.AccountExpiration.Value()
		c.AccountExpiration = &t
	case spec.AccountExpiration.IsClear():
		c.AccountExpiration = nil
	}
}

func (f *fakeComputer) Get(ctx context.Context, id adcore.Identity) (*adcore.Computer, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	o := f.s.findLocked(id)
	if o == nil || o.class != "computer" {
		return nil, notFound("Computer.Get", id)
	}
	m := o.computer
	return &m, nil
}

func (f *fakeComputer) Search(ctx context.Context, q adcore.Query) ([]adcore.Computer, error) {
	const op = "Computer.Search"
	q = q.WithDefaults(f.s.dnc)

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	var out []adcore.Computer
	for dn, o := range f.s.byDN {
		if o.class != "computer" || !inScope(dn, q) {
			continue
		}
		out = append(out, o.computer)
	}
	if len(out) > q.SizeLimit {
		return nil, tooMany(op, q.SizeLimit)
	}
	return out, nil
}

func (f *fakeComputer) Update(ctx context.Context, id adcore.Identity, spec adcore.ComputerSpec) (*adcore.Computer, error) {
	const op = "Computer.Update"
	if err := spec.Validate(op, false); err != nil {
		return nil, err
	}

	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil || o.class != "computer" {
		return nil, notFound(op, id)
	}
	if spec.PrincipalsAllowed != nil {
		principals, err := f.s.resolvePrincipalsLocked(op, spec.PrincipalsAllowed)
		if err != nil {
			return nil, err
		}
		o.computer.PrincipalsAllowed = principals
	}
	if spec.SamAccountName != "" {
		o.computer.SamAccountName = spec.SamAccountName
	}
	applyComputerSpec(&o.computer, spec)

	if spec.Name != o.computer.Name || !eqDN(spec.Container, o.computer.Container) {
		newDN := "CN=" + adcore.EscapeValue(spec.Name) + "," + spec.Container
		f.s.moveLocked(o, newDN)
		o.computer.DN, o.computer.Name, o.computer.Container = newDN, spec.Name, spec.Container
	}

	m := o.computer
	return &m, nil
}

func (f *fakeComputer) Delete(ctx context.Context, id adcore.Identity) error {
	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil || o.class != "computer" {
		return nil
	}
	delete(f.s.byDN, o.dn)
	return nil
}
