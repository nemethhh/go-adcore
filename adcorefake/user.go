package adcorefake

import (
	"context"
	"fmt"

	"github.com/nemethhh/go-adcore"
)

type fakeUser struct{ s *store }

var _ adcore.UserDirectory = (*fakeUser)(nil)

func (f *fakeUser) Create(ctx context.Context, spec adcore.UserSpec) (*adcore.User, error) {
	const op = "User.Create"
	if err := spec.Validate(op); err != nil {
		return nil, err
	}

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	name := spec.SamAccountName
	if spec.Name != nil && *spec.Name != "" {
		name = *spec.Name
	}
	dn := "CN=" + adcore.EscapeValue(name) + "," + spec.Container
	for have := range f.s.byDN {
		if eqDN(have, dn) {
			return nil, exists(op, dn)
		}
	}

	o := &object{guid: f.s.nextGUID(), dn: dn, class: "user"}
	o.user = adcore.User{
		GUID: o.guid, DN: dn, Name: name,
		SamAccountName: spec.SamAccountName, Container: spec.Container,
		// The defaults a new AD account has.
		Enabled: false, PasswordExpires: true, CanChangePassword: true,
		SID: "S-1-5-21-0-0-0-" + fmt.Sprint(f.s.seq),
	}
	applyUserSpec(&o.user, spec)
	f.s.byDN[dn] = o

	m := o.user
	return &m, nil
}

func applyUserSpec(u *adcore.User, spec adcore.UserSpec) {
	for _, f := range []struct {
		dst *string
		src *string
	}{
		{&u.UserPrincipalName, spec.UserPrincipalName},
		{&u.DisplayName, spec.DisplayName},
		{&u.GivenName, spec.GivenName},
		{&u.Surname, spec.Surname},
		{&u.Description, spec.Description},
	} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
	if spec.Enabled != nil {
		u.Enabled = *spec.Enabled
	}
	if spec.PasswordExpires != nil {
		u.PasswordExpires = *spec.PasswordExpires
	}
	if spec.ChangePasswordAtLogon != nil {
		u.ChangePasswordAtLogon = *spec.ChangePasswordAtLogon
	}
	if spec.CanChangePassword != nil {
		u.CanChangePassword = *spec.CanChangePassword
	}
	switch {
	case spec.AccountExpiration.IsSet():
		t := spec.AccountExpiration.Value()
		u.AccountExpiration = &t
	case spec.AccountExpiration.IsClear():
		u.AccountExpiration = nil
	}
}

func (f *fakeUser) Get(ctx context.Context, id adcore.Identity) (*adcore.User, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	o := f.s.findLocked(id)
	if o == nil || o.class != "user" {
		return nil, notFound("User.Get", id)
	}
	m := o.user
	return &m, nil
}

func (f *fakeUser) Search(ctx context.Context, q adcore.Query) ([]adcore.User, error) {
	const op = "User.Search"
	q = q.WithDefaults(f.s.dnc)

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	var out []adcore.User
	for dn, o := range f.s.byDN {
		if o.class != "user" || !inScope(dn, q) {
			continue
		}
		out = append(out, o.user)
	}
	if len(out) > q.SizeLimit {
		return nil, tooMany(op, q.SizeLimit)
	}
	return out, nil
}

func (f *fakeUser) Update(ctx context.Context, id adcore.Identity, spec adcore.UserSpec) (*adcore.User, error) {
	const op = "User.Update"
	if err := spec.Validate(op); err != nil {
		return nil, err
	}

	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil || o.class != "user" {
		return nil, notFound(op, id)
	}
	if spec.SamAccountName != "" {
		o.user.SamAccountName = spec.SamAccountName
	}
	applyUserSpec(&o.user, spec)

	name := o.user.Name
	if spec.Name != nil && *spec.Name != "" {
		name = *spec.Name
	}
	if name != o.user.Name || !eqDN(spec.Container, o.user.Container) {
		newDN := "CN=" + adcore.EscapeValue(name) + "," + spec.Container
		f.s.moveLocked(o, newDN)
		o.user.DN, o.user.Name, o.user.Container = newDN, name, spec.Container
	}

	m := o.user
	return &m, nil
}

func (f *fakeUser) Delete(ctx context.Context, id adcore.Identity) error {
	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil || o.class != "user" {
		return nil
	}
	delete(f.s.byDN, o.dn)
	return nil
}

func (f *fakeUser) SetPassword(ctx context.Context, id adcore.Identity, password adcore.Secret) error {
	const op = "User.SetPassword"
	if password.IsZero() {
		return &adcore.Error{Kind: adcore.KindPassword, Op: op,
			Err: fmt.Errorf("an empty password cannot be set")}
	}

	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	if o := f.s.findLocked(id); o == nil || o.class != "user" {
		return notFound(op, id)
	}
	return nil
}
