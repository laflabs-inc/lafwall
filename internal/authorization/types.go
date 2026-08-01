// Package authorization implements the transport- and storage-independent
// deny-by-default policy approved in RFC-0002.
package authorization

import "errors"

const maximumIdentifierBytes = 255

// ErrDenied is deliberately shared by malformed, unknown, cross-tenant, and
// insufficient-permission outcomes. Callers must not expose internal denial
// detail to clients.
var ErrDenied = errors.New("authorization denied")

// Permission is a closed internal action identifier. Adding or changing a
// permission requires a follow-up security-policy approval.
type Permission string

const (
	PermissionProjectCreate            Permission = "project:create"
	PermissionProjectRead              Permission = "project:read"
	PermissionProjectUpdate            Permission = "project:update"
	PermissionProjectArchive           Permission = "project:archive"
	PermissionProjectRestore           Permission = "project:restore"
	PermissionEnvironmentRead          Permission = "environment:read"
	PermissionSecretCreate             Permission = "secret:create"
	PermissionSecretReadMetadata       Permission = "secret:read_metadata"
	PermissionSecretWriteVersion       Permission = "secret:write_version"
	PermissionSecretReadValue          Permission = "secret:read_value"
	PermissionSecretReadHistory        Permission = "secret:read_history"
	PermissionSecretArchive            Permission = "secret:archive"
	PermissionSecretRestore            Permission = "secret:restore"
	PermissionServiceTokenCreate       Permission = "service_token:create"
	PermissionServiceTokenReadMetadata Permission = "service_token:read_metadata"
	PermissionServiceTokenRevoke       Permission = "service_token:revoke"
	PermissionRoleAssignmentRead       Permission = "role_assignment:read"
	PermissionRoleAssignmentManage     Permission = "role_assignment:manage"
	PermissionAuditRead                Permission = "audit:read"
)

var knownPermissions = [...]Permission{
	PermissionProjectCreate,
	PermissionProjectRead,
	PermissionProjectUpdate,
	PermissionProjectArchive,
	PermissionProjectRestore,
	PermissionEnvironmentRead,
	PermissionSecretCreate,
	PermissionSecretReadMetadata,
	PermissionSecretWriteVersion,
	PermissionSecretReadValue,
	PermissionSecretReadHistory,
	PermissionSecretArchive,
	PermissionSecretRestore,
	PermissionServiceTokenCreate,
	PermissionServiceTokenReadMetadata,
	PermissionServiceTokenRevoke,
	PermissionRoleAssignmentRead,
	PermissionRoleAssignmentManage,
	PermissionAuditRead,
}

// KnownPermissions returns a copy of the approved Permission vocabulary.
func KnownPermissions() []Permission {
	permissions := make([]Permission, len(knownPermissions))
	copy(permissions, knownPermissions[:])
	return permissions
}

// Valid reports whether the Permission belongs to the approved vocabulary.
func (p Permission) Valid() bool {
	for _, known := range knownPermissions {
		if p == known {
			return true
		}
	}
	return false
}

// Role is one of the five fixed MVP roles approved in RFC-0002.
type Role string

const (
	RoleTenantAdmin    Role = "tenant_admin"
	RoleProjectAdmin   Role = "project_admin"
	RoleSecretEditor   Role = "secret_editor"
	RoleSecretAccessor Role = "secret_accessor"
	RoleAuditor        Role = "auditor"
)

var knownRoles = [...]Role{
	RoleTenantAdmin,
	RoleProjectAdmin,
	RoleSecretEditor,
	RoleSecretAccessor,
	RoleAuditor,
}

// KnownRoles returns a copy of the approved Role vocabulary.
func KnownRoles() []Role {
	roles := make([]Role, len(knownRoles))
	copy(roles, knownRoles[:])
	return roles
}

// Valid reports whether the Role belongs to the approved vocabulary.
func (r Role) Valid() bool {
	for _, known := range knownRoles {
		if r == known {
			return true
		}
	}
	return false
}

// PrincipalKind distinguishes human and workload identities after successful
// authentication and authoritative Tenant mapping.
type PrincipalKind uint8

const (
	PrincipalHuman PrincipalKind = iota + 1
	PrincipalService
)

func (k PrincipalKind) valid() bool {
	return k == PrincipalHuman || k == PrincipalService
}

// Principal is an immutable authorization identity reference. principalID is
// a stable internal identifier, never an email, display name, or raw token.
type Principal struct {
	kind        PrincipalKind
	tenantID    string
	principalID string
}

// NewHumanPrincipal creates an authorization reference after an authenticated
// OIDC identity has been mapped to an internal Tenant principal.
func NewHumanPrincipal(tenantID, principalID string) (Principal, error) {
	return newPrincipal(PrincipalHuman, tenantID, principalID)
}

// NewServicePrincipal creates an authorization reference from a successfully
// authenticated, exact-Tenant-scoped service principal.
func NewServicePrincipal(tenantID, principalID string) (Principal, error) {
	return newPrincipal(PrincipalService, tenantID, principalID)
}

func newPrincipal(
	kind PrincipalKind,
	tenantID string,
	principalID string,
) (Principal, error) {
	principal := Principal{
		kind:        kind,
		tenantID:    tenantID,
		principalID: principalID,
	}
	if !principal.Valid() {
		return Principal{}, ErrDenied
	}
	return principal, nil
}

func (p Principal) Kind() PrincipalKind {
	return p.kind
}

func (p Principal) TenantID() string {
	return p.tenantID
}

func (p Principal) ID() string {
	return p.principalID
}

func (p Principal) Valid() bool {
	return p.kind.valid() &&
		validIdentifier(p.tenantID) &&
		validIdentifier(p.principalID)
}

func (Principal) String() string {
	return "authorization principal [redacted]"
}

func (Principal) GoString() string {
	return "authorization.Principal{redacted}"
}

// ScopeKind is the approved Tenant -> Project -> Environment hierarchy.
type ScopeKind uint8

const (
	ScopeTenant ScopeKind = iota + 1
	ScopeProject
	ScopeEnvironment
)

func (k ScopeKind) valid() bool {
	return k >= ScopeTenant && k <= ScopeEnvironment
}

// Scope contains canonical lineage resolved by an authoritative,
// Tenant-scoped lookup. It must never be assembled from unverified request IDs.
type Scope struct {
	kind          ScopeKind
	tenantID      string
	projectID     string
	environmentID string
}

func NewTenantScope(tenantID string) (Scope, error) {
	return newScope(ScopeTenant, tenantID, "", "")
}

func NewProjectScope(tenantID, projectID string) (Scope, error) {
	return newScope(ScopeProject, tenantID, projectID, "")
}

func NewEnvironmentScope(
	tenantID,
	projectID,
	environmentID string,
) (Scope, error) {
	return newScope(
		ScopeEnvironment,
		tenantID,
		projectID,
		environmentID,
	)
}

func newScope(
	kind ScopeKind,
	tenantID,
	projectID,
	environmentID string,
) (Scope, error) {
	scope := Scope{
		kind:          kind,
		tenantID:      tenantID,
		projectID:     projectID,
		environmentID: environmentID,
	}
	if !scope.Valid() {
		return Scope{}, ErrDenied
	}
	return scope, nil
}

func (s Scope) Kind() ScopeKind {
	return s.kind
}

func (s Scope) TenantID() string {
	return s.tenantID
}

func (s Scope) ProjectID() string {
	return s.projectID
}

func (s Scope) EnvironmentID() string {
	return s.environmentID
}

func (s Scope) Valid() bool {
	if !s.kind.valid() || !validIdentifier(s.tenantID) {
		return false
	}

	switch s.kind {
	case ScopeTenant:
		return s.projectID == "" && s.environmentID == ""
	case ScopeProject:
		return validIdentifier(s.projectID) && s.environmentID == ""
	case ScopeEnvironment:
		return validIdentifier(s.projectID) &&
			validIdentifier(s.environmentID)
	default:
		return false
	}
}

// Contains applies scope only downward. It never permits a child assignment
// to authorize its parent or sibling.
func (s Scope) Contains(target Scope) bool {
	if !s.Valid() || !target.Valid() || s.tenantID != target.tenantID {
		return false
	}

	switch s.kind {
	case ScopeTenant:
		return true
	case ScopeProject:
		return target.kind >= ScopeProject && s.projectID == target.projectID
	case ScopeEnvironment:
		return target.kind == ScopeEnvironment &&
			s.projectID == target.projectID &&
			s.environmentID == target.environmentID
	default:
		return false
	}
}

func (Scope) String() string {
	return "authorization scope [redacted]"
}

func (Scope) GoString() string {
	return "authorization.Scope{redacted}"
}

// ResourceKind identifies the semantic target independently from its scope.
// Secret and Environment targets can share an Environment scope without being
// interchangeable actions.
type ResourceKind uint8

const (
	ResourceTenant ResourceKind = iota + 1
	ResourceProject
	ResourceEnvironment
	ResourceSecret
	ResourceServiceToken
	ResourceRoleAssignment
	ResourceAudit
)

func (k ResourceKind) valid() bool {
	return k >= ResourceTenant && k <= ResourceAudit
}

// ResourceState carries the lifecycle precondition already resolved by the
// application. ParentArchived always denies; Archived permits only an approved
// restore action.
type ResourceState uint8

const (
	ResourceActive ResourceState = iota + 1
	ResourceArchived
	ResourceParentArchived
)

func (s ResourceState) valid() bool {
	return s >= ResourceActive && s <= ResourceParentArchived
}

// Target is a canonical resource lineage and lifecycle snapshot. Construction
// means the application has already performed an authoritative Tenant-scoped
// lookup; a zero Target represents unresolved or invalid lineage.
type Target struct {
	kind     ResourceKind
	scope    Scope
	state    ResourceState
	resolved bool
}

func NewTarget(
	kind ResourceKind,
	scope Scope,
	state ResourceState,
) (Target, error) {
	target := Target{
		kind:     kind,
		scope:    scope,
		state:    state,
		resolved: true,
	}
	if !target.Valid() {
		return Target{}, ErrDenied
	}
	return target, nil
}

func (t Target) Kind() ResourceKind {
	return t.kind
}

func (t Target) Scope() Scope {
	return t.scope
}

func (t Target) State() ResourceState {
	return t.state
}

func (t Target) Valid() bool {
	if !t.resolved || !t.kind.valid() || !t.scope.Valid() || !t.state.valid() {
		return false
	}

	switch t.kind {
	case ResourceTenant, ResourceServiceToken:
		return t.scope.kind == ScopeTenant
	case ResourceProject:
		return t.scope.kind == ScopeProject
	case ResourceEnvironment, ResourceSecret:
		return t.scope.kind == ScopeEnvironment
	case ResourceRoleAssignment, ResourceAudit:
		return true
	default:
		return false
	}
}

func (Target) String() string {
	return "authorization target [redacted]"
}

func (Target) GoString() string {
	return "authorization.Target{redacted}"
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > maximumIdentifierBytes {
		return false
	}

	for i := 0; i < len(value); i++ {
		character := value[i]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' ||
			character == '_' ||
			character == '.' ||
			character == '~' {
			continue
		}
		return false
	}
	return true
}

func denied() (Decision, error) {
	return Decision{}, ErrDenied
}
