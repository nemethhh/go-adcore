package adcorefake

import (
	"context"
	"fmt"

	"github.com/nemethhh/go-adcore"
)

type fakeGroup struct{ s *store }

var _ adcore.GroupDirectory = (*fakeGroup)(nil)

func (f *fakeGroup) Create(ctx context.Context, spec adcore.GroupSpec) (*adcore.Group, error) {
	const op = "Group.Create"
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

	o := &object{guid: f.s.nextGUID(), dn: dn, class: "group", members: map[string]bool{}}
	category := spec.Category
	if category == "" {
		category = adcore.GroupCategorySecurity
	}
	o.group = adcore.Group{
		GUID: o.guid, DN: dn, Name: spec.Name,
		SamAccountName: spec.SamAccountName, Container: spec.Container,
		Scope: spec.Scope, Category: category,
		SID: "S-1-5-21-0-0-0-" + fmt.Sprint(f.s.seq),
	}
	if spec.Description != nil {
		o.group.Description = *spec.Description
	}
	if spec.ManagedBy != nil {
		o.group.ManagedBy = *spec.ManagedBy
	}
	f.s.byDN[dn] = o

	m := o.group
	return &m, nil
}

func (f *fakeGroup) Get(ctx context.Context, id adcore.Identity) (*adcore.Group, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	o := f.s.findLocked(id)
	if o == nil || o.class != "group" {
		return nil, notFound("Group.Get", id)
	}
	m := o.group
	return &m, nil
}

func (f *fakeGroup) Search(ctx context.Context, q adcore.Query) ([]adcore.Group, error) {
	const op = "Group.Search"
	q = q.WithDefaults(f.s.dnc)

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	var out []adcore.Group
	for dn, o := range f.s.byDN {
		if o.class != "group" || !inScope(dn, q) {
			continue
		}
		out = append(out, o.group)
	}
	if len(out) > q.SizeLimit {
		return nil, tooMany(op, q.SizeLimit)
	}
	return out, nil
}

func (f *fakeGroup) Update(ctx context.Context, id adcore.Identity, spec adcore.GroupSpec) (*adcore.Group, error) {
	const op = "Group.Update"
	if err := spec.Validate(op, false); err != nil {
		return nil, err
	}

	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil || o.class != "group" {
		return nil, notFound(op, id)
	}
	if spec.SamAccountName != "" {
		o.group.SamAccountName = spec.SamAccountName
	}
	if spec.Scope != "" {
		o.group.Scope = spec.Scope
	}
	if spec.Category != "" {
		o.group.Category = spec.Category
	}
	if spec.Description != nil {
		o.group.Description = *spec.Description
	}
	if spec.ManagedBy != nil {
		o.group.ManagedBy = *spec.ManagedBy
	}
	if spec.Name != o.group.Name || !eqDN(spec.Container, o.group.Container) {
		newDN := "CN=" + adcore.EscapeValue(spec.Name) + "," + spec.Container
		f.s.moveLocked(o, newDN)
		o.group.DN, o.group.Name, o.group.Container = newDN, spec.Name, spec.Container
	}

	m := o.group
	return &m, nil
}

func (f *fakeGroup) Delete(ctx context.Context, id adcore.Identity) error {
	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil || o.class != "group" {
		return nil
	}
	delete(f.s.byDN, o.dn)
	return nil
}

func (f *fakeGroup) memberModelsLocked(o *object) []adcore.Member {
	out := make([]adcore.Member, 0, len(o.members))
	for guid := range o.members {
		for _, m := range f.s.byDN {
			if m.guid != guid {
				continue
			}
			out = append(out, adcore.Member{
				GUID: m.guid, DN: m.dn, Class: m.class,
				SID: m.group.SID + m.user.SID,
			})
		}
	}
	return out
}

func (f *fakeGroup) Members(ctx context.Context, id adcore.Identity) ([]adcore.Member, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	o := f.s.findLocked(id)
	if o == nil || o.class != "group" {
		return nil, notFound("Group.Members", id)
	}
	return f.memberModelsLocked(o), nil
}

// MembersRecursive walks nested groups and returns leaf accounts only, which
// is what both real backends return.
func (f *fakeGroup) MembersRecursive(ctx context.Context, id adcore.Identity) ([]adcore.Member, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	root := f.s.findLocked(id)
	if root == nil || root.class != "group" {
		return nil, notFound("Group.MembersRecursive", id)
	}

	seen := map[string]bool{}
	var out []adcore.Member
	var walk func(o *object)
	walk = func(o *object) {
		for guid := range o.members {
			if seen[guid] {
				continue
			}
			seen[guid] = true
			for _, m := range f.s.byDN {
				if m.guid != guid {
					continue
				}
				if m.class == "group" {
					walk(m)
					continue
				}
				out = append(out, adcore.Member{GUID: m.guid, DN: m.dn, Class: m.class, SID: m.user.SID})
			}
		}
	}
	walk(root)
	return out, nil
}

func (f *fakeGroup) AddMembers(ctx context.Context, id adcore.Identity, members []adcore.Identity) error {
	return f.editMembers("Group.AddMembers", id, members, true)
}

func (f *fakeGroup) RemoveMembers(ctx context.Context, id adcore.Identity, members []adcore.Identity) error {
	return f.editMembers("Group.RemoveMembers", id, members, false)
}

// editMembers is idempotent in both directions, matching the real backends:
// Terraform re-applies, so an add of an existing member and a removal of a
// non-member must converge rather than fail.
func (f *fakeGroup) editMembers(op string, id adcore.Identity, members []adcore.Identity, add bool) error {
	if len(members) == 0 {
		return nil
	}

	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil || o.class != "group" {
		return notFound(op, id)
	}
	for _, m := range members {
		target := f.s.findLocked(m)
		if target == nil {
			return notFound(op, m)
		}
		if add {
			o.members[target.guid] = true
		} else {
			delete(o.members, target.guid)
		}
	}
	return nil
}

func (f *fakeGroup) IsMember(ctx context.Context, id, member adcore.Identity) (bool, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil || o.class != "group" {
		return false, notFound("Group.IsMember", id)
	}
	target := f.s.findLocked(member)
	if target == nil {
		return false, notFound("Group.IsMember", member)
	}
	return o.members[target.guid], nil
}
