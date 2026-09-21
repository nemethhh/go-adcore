// Package adcore is the Active Directory vocabulary shared by every backend:
// the models a directory read returns, the specs a write takes, identities,
// queries, the normalized error Kind, and the invariant machinery
// (per-identity write locking, retry, delete verification) that every backend
// composes rather than reimplements.
//
// It performs no I/O, imports nothing outside the standard library, and knows
// nothing about PowerShell, LDAP or Terraform.
package adcore
