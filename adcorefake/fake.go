// Package adcorefake is an in-memory adcore.Directory.
//
// It implements the contract directly rather than simulating LDAP or
// PowerShell, so a consumer's tests run against either real backend or against
// this one with no protocol, no network and no Windows. adcoretest holds it to
// exactly the contract the real backends meet.
package adcorefake

import (
	"fmt"
	"strings"
	"sync"

	"github.com/nemethhh/go-adcore"
)

type object struct {
	guid  string
	dn    string
	class string

	ou    adcore.OU
	group adcore.Group
	user  adcore.User

	members map[string]bool // member GUIDs
}

type store struct {
	mu    sync.Mutex
	dnc   string
	byDN  map[string]*object
	seq   int
	locks *adcore.KeyedMutex

	// passwords records every password ever set, by GUID, so a test can
	// assert that a rotation actually happened. A Directory cannot express
	// that question, and asserting it only on one backend would leave the
	// other's password path untested.
	passwords map[string][]string
}

type noopCloser struct{}

func (noopCloser) Close() error { return nil }

// New returns an empty directory rooted at dnc.
func New(dnc string) adcore.Directory {
	d, _ := NewRecording(dnc)
	return d
}

// Recorder exposes what the fake observed, for assertions an adcore.Directory
// cannot express.
type Recorder struct{ s *store }

// Passwords returns the password history for every account, keyed by GUID.
func (r *Recorder) Passwords() map[string][]string {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	out := make(map[string][]string, len(r.s.passwords))
	for k, v := range r.s.passwords {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// NewRecording returns a directory and a handle on what it observed.
func NewRecording(dnc string) (adcore.Directory, *Recorder) {
	s := &store{
		dnc: dnc, byDN: map[string]*object{},
		locks: adcore.NewKeyedMutex(), passwords: map[string][]string{},
	}
	return adcore.Directory{
		OU:     &fakeOU{s: s},
		Group:  &fakeGroup{s: s},
		User:   &fakeUser{s: s},
		Server: "fake.corp.local",
		DNC:    dnc,
		Closer: noopCloser{},
	}, &Recorder{s: s}
}

func (s *store) nextGUID() string {
	s.seq++
	return fmt.Sprintf("%08x-0000-0000-0000-000000000000", s.seq)
}

// findLocked resolves an identity. The fake understands the same four forms
// the real backends do, so a test written against one works against this.
func (s *store) findLocked(id adcore.Identity) *object {
	arg := adcore.IdentityArg(id)
	switch adcore.IdentityForm(id) {
	case "guid":
		for _, o := range s.byDN {
			if o.guid == arg {
				return o
			}
		}
	case "dn":
		for dn, o := range s.byDN {
			if eqDN(dn, arg) {
				return o
			}
		}
	case "sam":
		for _, o := range s.byDN {
			if strings.EqualFold(o.group.SamAccountName, arg) || strings.EqualFold(o.user.SamAccountName, arg) {
				return o
			}
		}
	case "sid":
		for _, o := range s.byDN {
			if o.group.SID == arg || o.user.SID == arg {
				return o
			}
		}
	}
	return nil
}

func eqDN(a, b string) bool {
	eq, err := adcore.EqualFoldDN(a, b)
	return err == nil && eq
}

func notFound(op string, id adcore.Identity) error {
	return &adcore.Error{
		Kind: adcore.KindNotFound, Op: op, Identity: id.String(),
		Err: fmt.Errorf("no object matches %s", id),
	}
}

func exists(op, dn string) error {
	return &adcore.Error{
		Kind: adcore.KindAlreadyExists, Op: op, Target: dn,
		Err: fmt.Errorf("%q already exists", dn),
	}
}

func tooMany(op string, limit int) error {
	return &adcore.Error{
		Kind: adcore.KindTooManyResults, Op: op,
		Err: fmt.Errorf("more than %d objects matched; narrow the filter or raise the limit", limit),
	}
}

// childrenLocked counts objects directly beneath dn.
func (s *store) childrenLocked(dn string) int {
	n := 0
	for other := range s.byDN {
		if eqDN(other, dn) {
			continue
		}
		if strings.HasSuffix(strings.ToLower(other), ","+strings.ToLower(dn)) {
			n++
		}
	}
	return n
}

// moveLocked renames and moves an object in place, keeping its GUID and
// carrying its descendants with it — the property the contract cares about.
func (s *store) moveLocked(o *object, newDN string) {
	old := o.dn
	delete(s.byDN, old)
	o.dn = newDN
	s.byDN[newDN] = o

	for dn, child := range s.byDN {
		if dn == newDN || !strings.HasSuffix(strings.ToLower(dn), ","+strings.ToLower(old)) {
			continue
		}
		moved := dn[:len(dn)-len(old)] + newDN
		delete(s.byDN, dn)
		child.dn = moved
		s.byDN[moved] = child
		child.ou.DN, child.group.DN, child.user.DN = moved, moved, moved
	}
}

// inScope answers a Query's search base and scope.
func inScope(dn string, q adcore.Query) bool {
	base := q.SearchBase
	switch q.Scope {
	case adcore.SearchScopeBase:
		return eqDN(dn, base)
	case adcore.SearchScopeOneLevel:
		if eqDN(dn, base) {
			return false
		}
		rest := strings.TrimSuffix(strings.ToLower(dn), ","+strings.ToLower(base))
		return rest != strings.ToLower(dn) && !strings.Contains(rest, ",")
	default:
		return eqDN(dn, base) ||
			strings.HasSuffix(strings.ToLower(dn), ","+strings.ToLower(base))
	}
}

// recordPasswordLocked appends a password a spec carried, so a create followed
// by a rotation leaves a history of two.
func (s *store) recordPasswordLocked(guid string, password *adcore.Secret) {
	if password == nil || password.IsZero() {
		return
	}
	s.passwords[guid] = append(s.passwords[guid], adcore.RevealSecret(*password))
}
