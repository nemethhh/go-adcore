package adcorefake

import (
	"context"
	"fmt"

	"github.com/nemethhh/go-adcore"
)

type fakeOU struct{ s *store }

var _ adcore.OUDirectory = (*fakeOU)(nil)

func (f *fakeOU) Create(ctx context.Context, spec adcore.OUSpec) (*adcore.OU, error) {
	const op = "OU.Create"
	if err := adcore.ValidateName(op, spec.Name); err != nil {
		return nil, err
	}
	if err := adcore.ValidateContainer(op, spec.Container); err != nil {
		return nil, err
	}

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	dn := "OU=" + adcore.EscapeValue(spec.Name) + "," + spec.Container
	for have := range f.s.byDN {
		if eqDN(have, dn) {
			return nil, exists(op, dn)
		}
	}

	o := &object{guid: f.s.nextGUID(), dn: dn, class: "organizationalUnit"}
	o.ou = adcore.OU{GUID: o.guid, DN: dn, Name: spec.Name, Container: spec.Container}
	if spec.Description != nil {
		o.ou.Description = *spec.Description
	}
	if spec.Protected != nil {
		o.ou.Protected = *spec.Protected
	}
	f.s.byDN[dn] = o

	m := o.ou
	return &m, nil
}

func (f *fakeOU) Get(ctx context.Context, id adcore.Identity) (*adcore.OU, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	o := f.s.findLocked(id)
	if o == nil || o.class != "organizationalUnit" {
		return nil, notFound("OU.Get", id)
	}
	m := o.ou
	return &m, nil
}

func (f *fakeOU) Search(ctx context.Context, q adcore.Query) ([]adcore.OU, error) {
	const op = "OU.Search"
	q = q.WithDefaults(f.s.dnc)

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	var out []adcore.OU
	for dn, o := range f.s.byDN {
		if o.class != "organizationalUnit" || !inScope(dn, q) {
			continue
		}
		out = append(out, o.ou)
	}
	if len(out) > q.SizeLimit {
		return nil, tooMany(op, q.SizeLimit)
	}
	return out, nil
}

func (f *fakeOU) Update(ctx context.Context, id adcore.Identity, spec adcore.OUSpec) (*adcore.OU, error) {
	const op = "OU.Update"
	if err := adcore.ValidateName(op, spec.Name); err != nil {
		return nil, err
	}
	if err := adcore.ValidateContainer(op, spec.Container); err != nil {
		return nil, err
	}

	// The lock is held for the whole read-modify-write, which is what makes
	// concurrent updates to one identity serialize rather than interleave.
	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil || o.class != "organizationalUnit" {
		return nil, notFound(op, id)
	}
	if spec.Description != nil {
		o.ou.Description = *spec.Description
	}
	if spec.Protected != nil {
		o.ou.Protected = *spec.Protected
	}
	if spec.Name != o.ou.Name || !eqDN(spec.Container, o.ou.Container) {
		newDN := "OU=" + adcore.EscapeValue(spec.Name) + "," + spec.Container
		f.s.moveLocked(o, newDN)
		o.ou.DN, o.ou.Name, o.ou.Container = newDN, spec.Name, spec.Container
	}

	m := o.ou
	return &m, nil
}

func (f *fakeOU) Delete(ctx context.Context, id adcore.Identity, opts adcore.DeleteOptions) error {
	const op = "OU.Delete"

	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil || o.class != "organizationalUnit" {
		return nil // already absent: the desired state holds
	}
	if n := f.s.childrenLocked(o.dn); n > 0 {
		return &adcore.Error{
			Kind: adcore.KindConstraint, Op: op, Identity: id.String(), Target: o.dn,
			Err: fmt.Errorf("organizational unit has %d child object(s); delete or move them first", n),
		}
	}
	delete(f.s.byDN, o.dn)
	return nil
}
