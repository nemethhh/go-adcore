package adcorefake

import (
	"context"

	"github.com/nemethhh/go-adcore"
)

type fakeACL struct{ s *store }

var _ adcore.ACLDirectory = (*fakeACL)(nil)

func (f *fakeACL) Get(ctx context.Context, id adcore.Identity) ([]adcore.ACE, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	o := f.s.findLocked(id)
	if o == nil {
		return nil, notFound("ACL.Get", id)
	}
	return append([]adcore.ACE(nil), o.dacl...), nil
}

// Grant is idempotent on adcore.CanonicalACEKey, the same key both real
// backends compare on. A second notion of ACE equality here would let the fake
// accept a duplicate the directory would coalesce.
func (f *fakeACL) Grant(ctx context.Context, id adcore.Identity, list []adcore.ACE) error {
	const op = "ACL.Grant"
	if len(list) == 0 {
		return nil
	}

	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil {
		return notFound(op, id)
	}
	seen := make(map[string]struct{}, len(o.dacl))
	for _, a := range o.dacl {
		seen[adcore.CanonicalACEKey(a)] = struct{}{}
	}
	for _, a := range list {
		key := adcore.CanonicalACEKey(a)
		if _, ok := seen[key]; ok {
			continue
		}
		// Grant only ever writes explicit entries; an inherited one is a
		// stamped copy of a parent's and is never managed.
		a.Inherited = false
		o.dacl = append(o.dacl, a)
		seen[key] = struct{}{}
	}
	return nil
}

// Revoke removes by canonical key, so the order and case the caller wrote the
// rights in do not matter. Revoking something absent is not an error:
// Terraform destroys resources whose ACE somebody already removed by hand.
func (f *fakeACL) Revoke(ctx context.Context, id adcore.Identity, list []adcore.ACE) error {
	const op = "ACL.Revoke"
	if len(list) == 0 {
		return nil
	}

	unlock := f.s.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	o := f.s.findLocked(id)
	if o == nil {
		return notFound(op, id)
	}
	drop := make(map[string]struct{}, len(list))
	for _, a := range list {
		drop[adcore.CanonicalACEKey(a)] = struct{}{}
	}
	kept := make([]adcore.ACE, 0, len(o.dacl))
	for _, a := range o.dacl {
		if _, ok := drop[adcore.CanonicalACEKey(a)]; ok && !a.Inherited {
			continue
		}
		kept = append(kept, a)
	}
	o.dacl = kept
	return nil
}
