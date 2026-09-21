package adcorefake

import (
	"context"
	"fmt"

	"github.com/nemethhh/go-adcore"
)

type fakeSchema struct{ s *store }

var _ adcore.SchemaDirectory = (*fakeSchema)(nil)

// wellKnownGUIDs are the names a consumer's suites actually resolve. This is
// not the schema — only what is asked for is here, and a name that is missing
// is an error rather than an empty answer, because an ACE built with an empty
// object type means "every property".
var wellKnownGUIDs = map[string]string{
	"user":           "bf967aba-0de6-11d0-a285-00aa003049e2",
	"group":          "bf967a9c-0de6-11d0-a285-00aa003049e2",
	"computer":       "bf967a86-0de6-11d0-a285-00aa003049e2",
	"member":         "bf9679c0-0de6-11d0-a285-00aa003049e2",
	"pwdLastSet":     "bf967a0a-0de6-11d0-a285-00aa003049e2",
	"Reset Password": "00299570-246d-11d0-a768-00aa006e0529",
}

// Resolve mirrors both real backends: a name that is already a GUID is passed
// through without a lookup, and an unresolvable one is an error naming it.
func (f *fakeSchema) Resolve(ctx context.Context, refs []adcore.SchemaRef) (map[adcore.SchemaRef]string, error) {
	const op = "Schema.Resolve"
	out := make(map[adcore.SchemaRef]string, len(refs))
	for _, ref := range refs {
		if _, ok := out[ref]; ok {
			continue
		}
		if isGUIDString(ref.Name) {
			out[ref] = ref.Name
			continue
		}
		guid, ok := wellKnownGUIDs[ref.Name]
		if !ok {
			return nil, &adcore.Error{Kind: adcore.KindNotFound, Op: op,
				Err: fmt.Errorf("no %s named %q exists in the schema", string(ref.Kind), ref.Name)}
		}
		out[ref] = guid
	}
	return out, nil
}

// isGUIDString reports whether a name is already the canonical 8-4-4-4-12 form.
func isGUIDString(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
