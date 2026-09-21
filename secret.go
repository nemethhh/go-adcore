package adcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Secret carries a password without letting it reach a log line, a state file,
// or a %v verb. Its plaintext is readable only through RevealSecret, which a
// backend's payload builder calls deliberately at the moment of serialization.
// The guarantee is on the type, not on each call site.
type Secret struct {
	v string
}

// NewSecret wraps a plaintext password.
func NewSecret(s string) Secret { return Secret{v: s} }

// String makes %v, %s and the print helpers safe.
func (Secret) String() string { return "REDACTED" }

// GoString makes %#v safe.
func (Secret) GoString() string { return "adcore.Secret{REDACTED}" }

// Format makes every verb safe, not just the string ones. fmt consults a
// Stringer only for %v, %s, %q, %x and %X; under %d it walks the struct and
// prints the field, so a Stringer alone leaks the plaintext as
// "{%!d(string=hunter2)}". Implementing Formatter is what makes "a Secret
// never reaches a log line" true whatever verb the log line happens to use.
func (s Secret) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		io.WriteString(f, s.GoString())
		return
	}
	io.WriteString(f, s.String())
}

// MarshalJSON always fails. A Secret must be revealed deliberately; it must
// never be serialized by a struct walk into a log line or a state file.
func (Secret) MarshalJSON() ([]byte, error) {
	return nil, errors.New("adcore: Secret must not be marshalled; reveal it deliberately with RevealSecret")
}

// IsZero reports whether the secret was never set.
func (s Secret) IsZero() bool { return s.v == "" }

// RevealSecret returns the plaintext. It is a function rather than a method so
// that every site that extracts a password is greppable by name — which is the
// property Secret exists to provide.
func RevealSecret(s Secret) string { return s.v }

var (
	_ json.Marshaler = Secret{}
	_ fmt.Formatter  = Secret{}
)
