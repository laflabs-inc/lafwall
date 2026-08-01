package authorization

// AssignmentStatus represents immutable assignment lifecycle state.
type AssignmentStatus uint8

const (
	AssignmentActive AssignmentStatus = iota + 1
	AssignmentRevoked
)

func (s AssignmentStatus) valid() bool {
	return s == AssignmentActive || s == AssignmentRevoked
}

// Assignment is an immutable Role grant. A later storage boundary must create
// and revoke it together with the mandatory audit event in one transaction.
type Assignment struct {
	principal Principal
	role      Role
	scope     Scope
	status    AssignmentStatus
}

// NewAssignment validates Principal eligibility and the exact approved scope
// for a Role. It reconstructs authoritative state; it does not authorize or
// persist a grant. Use Policy.Grant for a grant decision.
func NewAssignment(
	principal Principal,
	role Role,
	scope Scope,
) (Assignment, error) {
	assignment := Assignment{
		principal: principal,
		role:      role,
		scope:     scope,
		status:    AssignmentActive,
	}
	if !assignment.Valid() {
		return Assignment{}, ErrDenied
	}
	return assignment, nil
}

func (a Assignment) Principal() Principal {
	return a.principal
}

func (a Assignment) Role() Role {
	return a.role
}

func (a Assignment) Scope() Scope {
	return a.scope
}

func (a Assignment) Status() AssignmentStatus {
	return a.status
}

func (a Assignment) Active() bool {
	return a.Valid() && a.status == AssignmentActive
}

func (a Assignment) Valid() bool {
	return a.status.valid() &&
		a.principal.Valid() &&
		a.role.Valid() &&
		a.scope.Valid() &&
		a.principal.tenantID == a.scope.tenantID &&
		principalEligible(a.principal.kind, a.role) &&
		roleScopeEligible(a.role, a.scope.kind)
}

// Revoke returns a new immutable lifecycle value and leaves the input active.
// Persistence and the mandatory audit event remain an application concern.
func (a Assignment) Revoke() (Assignment, error) {
	if !a.Valid() {
		return Assignment{}, ErrDenied
	}
	if a.status == AssignmentRevoked {
		return a, nil
	}

	revoked := a
	revoked.status = AssignmentRevoked
	return revoked, nil
}

func (Assignment) String() string {
	return "role assignment [redacted]"
}

func (Assignment) GoString() string {
	return "authorization.Assignment{redacted}"
}

func principalEligible(kind PrincipalKind, role Role) bool {
	switch kind {
	case PrincipalHuman:
		return role.Valid()
	case PrincipalService:
		return role == RoleSecretEditor || role == RoleSecretAccessor
	default:
		return false
	}
}

func roleScopeEligible(role Role, kind ScopeKind) bool {
	switch role {
	case RoleTenantAdmin:
		return kind == ScopeTenant
	case RoleProjectAdmin:
		return kind == ScopeProject
	case RoleSecretEditor, RoleSecretAccessor:
		return kind == ScopeProject || kind == ScopeEnvironment
	case RoleAuditor:
		return kind.valid()
	default:
		return false
	}
}
