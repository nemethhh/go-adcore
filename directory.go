package adcore

import (
	"context"
	"io"
)

// Directory is what a backend hands a consumer. It is a struct of interfaces
// rather than an interface of accessors so that a backend whose sub-clients
// are already struct fields satisfies it without changing its own API.
//
// Every guarantee a consumer relies on — read-back after write, delete
// verification, a pinned domain controller, serialized writes per identity —
// is the implementation's to uphold. RunDirectorySuite in adcoretest asserts
// them behaviourally against any implementation.
type Directory struct {
	OU             OUDirectory
	Group          GroupDirectory
	User           UserDirectory
	ServiceAccount ServiceAccountDirectory
	Computer       ComputerDirectory
	ACL            ACLDirectory
	Schema         SchemaDirectory

	// Server is the pinned domain controller every operation targets.
	Server string
	// DNC is the domain's default naming context, e.g. "DC=corp,DC=local".
	DNC string

	Closer io.Closer
}

// Close releases the backend's resources.
func (d Directory) Close() error {
	if d.Closer == nil {
		return nil
	}
	return d.Closer.Close()
}

// Only OU.Delete takes DeleteOptions. Unprotecting before a delete is an
// OU-shaped concern — AD's own default protects an OU and nothing else — and
// giving the other classes an options argument they ignore would advertise a
// choice that does not exist.

type OUDirectory interface {
	Create(ctx context.Context, spec OUSpec) (*OU, error)
	Get(ctx context.Context, id Identity) (*OU, error)
	Search(ctx context.Context, q Query) ([]OU, error)
	Update(ctx context.Context, id Identity, spec OUSpec) (*OU, error)
	Delete(ctx context.Context, id Identity, opts DeleteOptions) error
}

type GroupDirectory interface {
	Create(ctx context.Context, spec GroupSpec) (*Group, error)
	Get(ctx context.Context, id Identity) (*Group, error)
	Search(ctx context.Context, q Query) ([]Group, error)
	Update(ctx context.Context, id Identity, spec GroupSpec) (*Group, error)
	Delete(ctx context.Context, id Identity) error

	Members(ctx context.Context, id Identity) ([]Member, error)
	MembersRecursive(ctx context.Context, id Identity) ([]Member, error)
	AddMembers(ctx context.Context, id Identity, members []Identity) error
	RemoveMembers(ctx context.Context, id Identity, members []Identity) error
	IsMember(ctx context.Context, id, member Identity) (bool, error)
}

type UserDirectory interface {
	Create(ctx context.Context, spec UserSpec) (*User, error)
	Get(ctx context.Context, id Identity) (*User, error)
	Search(ctx context.Context, q Query) ([]User, error)
	Update(ctx context.Context, id Identity, spec UserSpec) (*User, error)
	Delete(ctx context.Context, id Identity) error
	SetPassword(ctx context.Context, id Identity, password Secret) error
}

type ServiceAccountDirectory interface {
	Create(ctx context.Context, spec GMSASpec) (*GMSA, error)
	Get(ctx context.Context, id Identity) (*GMSA, error)
	Search(ctx context.Context, q Query) ([]GMSA, error)
	Update(ctx context.Context, id Identity, spec GMSASpec) (*GMSA, error)
	Delete(ctx context.Context, id Identity) error
}

type ComputerDirectory interface {
	Create(ctx context.Context, spec ComputerSpec) (*Computer, error)
	Get(ctx context.Context, id Identity) (*Computer, error)
	Search(ctx context.Context, q Query) ([]Computer, error)
	Update(ctx context.Context, id Identity, spec ComputerSpec) (*Computer, error)
	Delete(ctx context.Context, id Identity) error
}

// ACL takes resolved ACEs, not the friendly ACESpec a delegation template
// emits: resolving a name to a schema GUID is a directory read, so it belongs
// to the caller that already holds a Schema, not to the write.
type ACLDirectory interface {
	Get(ctx context.Context, id Identity) ([]ACE, error)
	Grant(ctx context.Context, id Identity, aces []ACE) error
	Revoke(ctx context.Context, id Identity, aces []ACE) error
}

// Resolve is batched because the round trip is per call, not per name: an ACL
// grant resolves a dozen names at once and a one-at-a-time signature would
// make that a dozen searches.
type SchemaDirectory interface {
	Resolve(ctx context.Context, refs []SchemaRef) (map[SchemaRef]string, error)
}
