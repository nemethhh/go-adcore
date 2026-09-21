package adcore

import (
	"errors"
	"fmt"
)

// OUSpec is the desired state of an organizational unit. A nil pointer leaves
// the attribute alone; a pointer to "" clears it; a pointer to a value sets it.
type OUSpec struct {
	Name        string // the RDN; required on create, a change means Rename-ADObject
	Container   string // parent DN; required on create, a change means Move-ADObject
	Description *string
	Protected   *bool // ProtectedFromAccidentalDeletion
}

// DeleteOptions is taken only by OU.Delete. Making the unprotect step an
// explicit option keeps the destructive part visible at the call site.
type DeleteOptions struct {
	// Unprotect lifts ProtectedFromAccidentalDeletion before deleting. Without
	// it, deleting an OU created with AD's own default fails.
	Unprotect bool
}

// ValidateContainer rejects a container that is empty or is not a
// distinguished name, before any round trip.
func ValidateContainer(op, container string) error {
	if container == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Container is required")}
	}
	if _, err := ParseDN(container); err != nil {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Container is not a distinguished name: %w", err)}
	}
	return nil
}

// ValidateName rejects an empty name before any round trip.
func ValidateName(op, name string) error {
	if name == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Name is required")}
	}
	return nil
}

// PresenceCheck is the result of re-reading an object after a delete. The
// probe never decides whether an object is gone: it hands the failure back so
// the backend's classifier, which fails closed, makes the call.
//
// Kind is the backend's own classification of the probe's failure. It is a
// field rather than something ConfirmAbsent derives because the two backends
// classify from different evidence — go-adpwsh from the .NET exception type
// the ActiveDirectory module raises, go-adldap from an LDAP result code — and
// neither vocabulary belongs in a backend-neutral module.
type PresenceCheck struct {
	// Present reports whether the object was still resolvable. The JSON tag
	// is the name the PowerShell probe writes and must not be renamed with
	// the field.
	Present       bool   `json:"found"`
	ExceptionType string `json:"type"`
	ErrorCode     int    `json:"errorCode"`
	Message       string `json:"message"`

	Kind Kind `json:"-"`
}

// ConfirmAbsent turns a presence probe into the delete verdict. A destroy that
// silently no-ops is worse than one that fails: Terraform drops the resource
// from state and the object is then unmanaged and invisible.
func (p PresenceCheck) ConfirmAbsent(op string, id Identity, dn string) error {
	if p.Present {
		return &Error{
			Kind: KindConstraint, Op: op, Identity: id.String(), Target: dn,
			Err: fmt.Errorf("the remove cmdlet returned cleanly but the object is still present; " +
				"the deletion was refused"),
		}
	}
	// A probe that reported no failure at all found nothing and had nothing
	// to classify; the object is gone. Only a probe that failed needs its
	// Kind consulted, and a failure that is not "not found" has verified
	// nothing: treating a server-down as a successful delete is the bug this
	// whole check exists to prevent.
	if p.ExceptionType == "" && p.ErrorCode == 0 && p.Kind == KindUnknown {
		return nil
	}
	if p.Kind != KindNotFound {
		return &Error{
			Kind: p.Kind, Op: op, Identity: id.String(), Target: dn,
			ExceptionType: p.ExceptionType, Code: p.ErrorCode, ServerMessage: p.Message,
			Err: fmt.Errorf("could not verify the deletion"),
		}
	}
	return nil
}

// WithIdentity stamps the identity onto an error a backend returned, so a
// diagnostic can name what was acted on.
func WithIdentity(err error, op string, id Identity) error {
	var e *Error
	if errors.As(err, &e) {
		if e.Op == "" {
			e.Op = op
		}
		if e.Identity == "" {
			e.Identity = id.String()
		}
		return e
	}
	return err
}

// GroupSpec is the desired state of a group.
type GroupSpec struct {
	Name           string // the CN; a change means Rename-ADObject
	SamAccountName string // required; changes through Set-ADGroup
	Container      string // parent DN; a change means Move-ADObject
	Scope          GroupScope
	Category       GroupCategory // defaults to security
	Description    *string
	ManagedBy      *string
}

func (s GroupSpec) Validate(op string, forCreate bool) error {
	if err := ValidateName(op, s.Name); err != nil {
		return err
	}
	if s.SamAccountName == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("SamAccountName is required")}
	}
	if err := ValidateContainer(op, s.Container); err != nil {
		return err
	}
	// -GroupScope is a mandatory parameter of New-ADGroup, so there is no
	// meaningful default to fall back on.
	if forCreate && s.Scope == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Scope is required (global, domainlocal or universal)")}
	}
	switch s.Scope {
	case "", GroupScopeGlobal, GroupScopeDomainLocal, GroupScopeUniversal:
	default:
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Scope %q is not one of global, domainlocal, universal", s.Scope)}
	}
	switch s.Category {
	case "", GroupCategorySecurity, GroupCategoryDistribution:
	default:
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("Category %q is not one of security, distribution", s.Category)}
	}
	return nil
}

// UserSpec is the desired state of a user account.
type UserSpec struct {
	SamAccountName    string  // required on create
	Container         string  // required on create; a change means Move-ADObject
	Name              *string // the CN; defaults to SamAccountName on create; a change means Rename-ADObject
	UserPrincipalName *string
	DisplayName       *string
	GivenName         *string
	Surname           *string
	Description       *string

	Enabled               *bool
	Password              *Secret
	ChangePasswordAtLogon *bool
	CanChangePassword     *bool
	PasswordExpires       *bool
	AccountExpiration     OptTime
}

func (s UserSpec) Validate(op string) error {
	if s.SamAccountName == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("SamAccountName is required")}
	}
	if err := ValidateContainer(op, s.Container); err != nil {
		return err
	}
	if s.AccountExpiration.IsSet() && s.AccountExpiration.IsClear() {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("AccountExpiration cannot both set and clear")}
	}
	// Correctness rule 7. AD accepts these combinations and then behaves in a
	// way nobody asked for, so they are refused before a round trip.
	if s.ChangePasswordAtLogon != nil && *s.ChangePasswordAtLogon {
		if s.PasswordExpires != nil && !*s.PasswordExpires {
			return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf(
				"change_password_at_logon cannot be true while password_expires is false: " +
					"AD cannot require a change of a password that never expires")}
		}
		if s.CanChangePassword != nil && !*s.CanChangePassword {
			return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf(
				"change_password_at_logon cannot be true while can_change_password is false: " +
					"the user would be required to do what they are denied")}
		}
	}
	return nil
}

// GMSASpec is the desired state of a group Managed Service Account. Pointer
// fields follow the tri-state convention: nil leaves the attribute alone, a
// pointer to "" clears it, a pointer to a value sets it.
type GMSASpec struct {
	Name                          string // CN; required
	SamAccountName                string // required; <= 15 chars, "$" is added by AD
	Container                     string // parent DN; required
	DNSHostName                   *string
	Description                   *string
	DisplayName                   *string
	Enabled                       *bool
	TrustedForDelegation          *bool
	PrincipalsAllowed             []Identity // full-replace; nil leaves alone, non-nil (incl. empty) replaces
	ServicePrincipalNames         *[]string  // nil leaves alone, non-nil (incl. empty) replaces
	KerberosEncryptionType        *[]string  // nil leaves alone, non-nil replaces
	AccountExpiration             OptTime
	ManagedPasswordIntervalInDays *int // create-only; ignored on Update
}

const gmsaSamMaxLen = 15

// forCreate follows the same convention GroupSpec.Validate uses: the op
// string is for error stamping only, never for branching. Branching on it
// (as an earlier version of this method did, comparing op == "GMSA.Create")
// silently breaks the moment a caller's op string doesn't match that literal
// — which is exactly what happened here, since ServiceAccountClient.Create
// (following the <Resource>.<Verb> convention every other sub-client uses)
// passes "ServiceAccount.Create", not "GMSA.Create".
func (s GMSASpec) Validate(op string, forCreate bool) error {
	if err := ValidateName(op, s.Name); err != nil {
		return err
	}
	if s.SamAccountName == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("SamAccountName is required")}
	}
	if len(s.SamAccountName) > gmsaSamMaxLen {
		return &Error{Kind: KindConstraint, Op: op,
			Err: fmt.Errorf("SamAccountName %q is %d characters; a gMSA sAMAccountName must be at most %d", s.SamAccountName, len(s.SamAccountName), gmsaSamMaxLen)}
	}
	if err := ValidateContainer(op, s.Container); err != nil {
		return err
	}
	if forCreate && (s.DNSHostName == nil || *s.DNSHostName == "") {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("DNSHostName is required")}
	}
	return nil
}

// ComputerSpec is the desired state of a computer account. Pointer fields
// follow the same tri-state convention as GMSASpec: nil leaves the attribute
// alone, a pointer to "" clears it, a pointer to a value sets it.
//
// Unlike GMSASpec, SamAccountName has no length cap here: the 15-char
// NetBIOS limit gMSA enforces is a gMSA-specific constraint (the "$" AD
// appends must still fit in 20 bytes downlevel-logon-name space), not a
// general AD rule — AD accepts a computer sAMAccountName well past 15
// characters, so validate must not reject one. There are also no
// create-only fields: DNSHostName, unlike a gMSA's, is settable any time.
type ComputerSpec struct {
	Name                   string // CN; required
	SamAccountName         string // required; "$" is added by AD; length is NOT capped here
	Container              string // parent DN; required
	DNSHostName            *string
	Description            *string
	DisplayName            *string
	Location               *string
	ManagedBy              *string
	Enabled                *bool
	TrustedForDelegation   *bool
	ServicePrincipalNames  *[]string  // nil leaves alone, non-nil (incl. empty) replaces
	AllowedToDelegateTo    *[]string  // nil leaves alone, non-nil (incl. empty) replaces
	PrincipalsAllowed      []Identity // full-replace; nil leaves alone, non-nil (incl. empty) replaces
	KerberosEncryptionType *[]string  // nil leaves alone, non-nil replaces
	AccountExpiration      OptTime
}

func (s ComputerSpec) Validate(op string, forCreate bool) error {
	if err := ValidateName(op, s.Name); err != nil {
		return err
	}
	if s.SamAccountName == "" {
		return &Error{Kind: KindConstraint, Op: op, Err: fmt.Errorf("SamAccountName is required")}
	}
	if err := ValidateContainer(op, s.Container); err != nil {
		return err
	}
	return nil
}
