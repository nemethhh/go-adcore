# go-adcore

The Active Directory vocabulary shared by every backend: the models a
directory read returns, the specs a write takes, identities, queries, the
normalized error `Kind`, and the invariant machinery every backend composes
rather than reimplements.

It performs no I/O, imports nothing outside the standard library, and knows
nothing about PowerShell, LDAP or Terraform.

## Why it exists

[`go-adpwsh`](https://github.com/nemethhh/go-adpwsh) drives Active Directory
through PowerShell. A second backend drives it over LDAP. Both must return the
same models, take the same specs, and classify the same condition as the same
`Kind` — otherwise a Terraform provider switching between them is switching
between two subtly different directories.

That agreement is this module. `go-adpwsh` re-exports all of it as type
aliases, so `adpwsh.OU` and `adcore.OU` are one type, not two convertible
ones.

## What is here

| File | Responsibility |
|---|---|
| `models.go` | `OU`, `Group`, `User`, `GMSA`, `Computer`, `Member`, `OptTime`, pointer helpers |
| `identity.go` | the sealed `Identity` interface and its four constructors |
| `secret.go` | `Secret`, `RevealSecret` |
| `errors.go` | `Kind`, `Error`, the sentinels, the MS-ERREF code table |
| `spec.go` | the `*Spec` types, their validators, `PresenceCheck`, `WithIdentity` |
| `search.go` | `Query`, `SearchScope` |
| `acl.go` | ACE/ACL types, `CanonicalACEKey` |
| `delegation.go` | `Delegation` — pure expansion of a curated task into ACEs |
| `dn.go`, `filter.go` | RFC 4514 DNs and RFC 4515 filter escaping |
| `directory.go` | the `Directory` struct of interfaces |
| `locks.go`, `retry.go` | `KeyedMutex`, `RetryConfig`, `Backoff` |
| `schema/` | the schema catalog and its reader |
| `adcoretest/` | `RunDirectorySuite` — the behavioural conformance suite |

## Three rules this module keeps

**No third-party dependencies.** Standard library only, enforced by
`TestNoThirdPartyDependencies`. This is the shared vocabulary for two backends
and a Terraform provider; a dependency here is a dependency everywhere.

**`Identity` stays sealed across a module boundary.** The interface's methods
are unexported, so the only values satisfying it come from `ByGUID`, `ByDN`,
`BySID` and `BySAM`. Backends read the parts through the `IdentityArg` and
`IdentityForm` *functions* — exporting the methods instead would let any
package hand a backend an arbitrary string as an identity, which is what keeps
a caller's value from becoming PowerShell script text or an unescaped LDAP
filter term.

**A `Secret` never reaches a log line.** It renders `REDACTED` under every
`fmt` verb — via `fmt.Formatter`, not merely `Stringer`, because `%d` on a
struct walks the fields — and its `MarshalJSON` always fails. The plaintext is
reachable only through `RevealSecret`, a function rather than a method so that
every site extracting a password is greppable by name.

## Conformance

The guarantees a consumer relies on — read-back after write, delete
verification, a pinned domain controller, serialized writes per identity, a
search that errors rather than truncating, a rename that never replaces the
object — were once enforced structurally, by a single implementation no
backend could opt out of. With backends in separate modules that is no longer
possible, so they are behavioural assertions:

```go
func TestMyBackendConformance(t *testing.T) {
	adcoretest.RunDirectorySuite(t, func(t *testing.T) adcore.Directory {
		return newMyBackend(t).Directory()
	})
}
```

A backend that does not run `RunDirectorySuite` is not a conforming
implementation.

## Attribution

`dn.go` and `filter.go` are a reimplementation of the slice of RFC 4514 and
RFC 4515 this module needs, rather than a dependency on
[`go-ldap`](https://github.com/go-ldap/ldap) — which would pull Kerberos,
NTLM, SSPI and BER into a module that performs no I/O, and which the
no-third-party-imports rule forbids outright. The test vectors are ported from
that project (MIT licence), so the reimplementation stays pinned to a
maintained parser's behaviour.

## Licence

MIT. See [LICENSE](LICENSE).
