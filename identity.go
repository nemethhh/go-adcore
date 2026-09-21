package adcore

// Identity is an AD identity argument. The interface is sealed by unexported
// methods: the only values that satisfy it come from the four constructors
// below, so no caller can hand a backend an arbitrary string as an identity —
// which is what keeps a caller's value from becoming PowerShell script text or
// an unescaped LDAP filter term.
//
// Backends in other modules read the parts through IdentityArg and
// IdentityForm. Those are functions rather than interface methods precisely so
// that the seal survives the module boundary: exporting the methods would let
// any package implement Identity.
type Identity interface {
	identityArg() string
	identityForm() string
	String() string
}

type identity struct {
	arg  string
	form string
}

func (i identity) identityArg() string  { return i.arg }
func (i identity) identityForm() string { return i.form }
func (i identity) String() string       { return i.form + ":" + i.arg }

// IdentityArg returns the identity's value.
func IdentityArg(id Identity) string { return id.identityArg() }

// IdentityForm returns the identity's form: "guid", "dn", "sid" or "sam".
func IdentityForm(id Identity) string { return id.identityForm() }

// ByGUID identifies an object by objectGUID. This is the canonical form: it
// survives rename and move, which DN and sAMAccountName do not.
func ByGUID(guid string) Identity { return identity{arg: guid, form: "guid"} }

// ByDN identifies an object by distinguished name.
func ByDN(dn string) Identity { return identity{arg: dn, form: "dn"} }

// BySID identifies a security principal by SID.
func BySID(sid string) Identity { return identity{arg: sid, form: "sid"} }

// BySAM identifies a security principal by sAMAccountName.
func BySAM(sam string) Identity { return identity{arg: sam, form: "sam"} }
