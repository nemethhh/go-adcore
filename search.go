package adcore

// SearchScope is the depth a directory search descends to.
type SearchScope string

const (
	SearchScopeBase     SearchScope = "base"
	SearchScopeOneLevel SearchScope = "onelevel"
	SearchScopeSubtree  SearchScope = "subtree"
)

// DefaultSizeLimit caps a search unless the caller sets its own limit. Large
// enough for a realistic subtree, small enough that a domain-wide accident
// errors rather than dragging.
const DefaultSizeLimit = 1000

// Query is a directory search. The zero value searches the whole domain subtree
// for every object of the sub-client's class, capped at the default limit.
type Query struct {
	Filter     string      // a COMPLETE LDAP filter; "" ⇒ "(objectClass=*)"
	SearchBase string      // DN; "" ⇒ the pinned domain's defaultNamingContext
	Scope      SearchScope // "" ⇒ subtree
	SizeLimit  int         // ≤ 0 ⇒ DefaultSizeLimit
}

// WithDefaults resolves the zero-value fields against the pinned domain.
func (q Query) WithDefaults(dnc string) Query {
	if q.SearchBase == "" {
		q.SearchBase = dnc
	}
	if q.Scope == "" {
		q.Scope = SearchScopeSubtree
	}
	if q.SizeLimit <= 0 {
		q.SizeLimit = DefaultSizeLimit
	}
	return q
}
