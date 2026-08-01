package authorization

// Policy is the pure deny-by-default authorization boundary. Its zero value is
// ready for use and contains no cache, I/O, logging, or mutable policy state.
type Policy struct{}

// Decision is an immutable result for one authoritative input snapshot.
// A successful decision must not be reused after authentication, assignment,
// target lineage, or lifecycle state changes.
type Decision struct {
	allowed bool
}

func (d Decision) Allowed() bool {
	return d.allowed
}

func (Decision) String() string {
	return "authorization decision [redacted]"
}

func (Decision) GoString() string {
	return "authorization.Decision{redacted}"
}

// Authorize evaluates one Principal, exact action, resolved target, and an
// authoritative snapshot containing only that Principal's assignments.
// Unknown or malformed state anywhere in the snapshot denies the operation.
func (Policy) Authorize(
	principal Principal,
	permission Permission,
	target Target,
	assignments []Assignment,
) (Decision, error) {
	if !principal.Valid() ||
		!permission.Valid() ||
		!target.Valid() ||
		principal.tenantID != target.scope.tenantID ||
		permissionTarget(permission) != target.kind ||
		!lifecycleAllows(permission, target.state) ||
		len(assignments) == 0 {
		return denied()
	}

	allowed := false
	for _, assignment := range assignments {
		if !assignment.Valid() || assignment.principal != principal {
			return denied()
		}
		if assignment.status == AssignmentActive &&
			assignment.scope.Contains(target.scope) &&
			roleAllows(assignment.role, permission) {
			allowed = true
		}
	}

	if !allowed {
		return denied()
	}
	return Decision{allowed: true}, nil
}

// PermissionsForRole returns a fresh copy of the exact RFC-0002 matrix row.
// An unknown Role returns no Permission.
func PermissionsForRole(role Role) []Permission {
	if !role.Valid() {
		return nil
	}

	permissions := make([]Permission, 0, len(knownPermissions))
	for _, permission := range knownPermissions {
		if roleAllows(role, permission) {
			permissions = append(permissions, permission)
		}
	}
	return permissions
}

func roleAllows(role Role, permission Permission) bool {
	if !role.Valid() || !permission.Valid() {
		return false
	}

	switch role {
	case RoleTenantAdmin:
		switch permission {
		case PermissionProjectCreate,
			PermissionProjectRead,
			PermissionProjectUpdate,
			PermissionProjectArchive,
			PermissionProjectRestore,
			PermissionEnvironmentRead,
			PermissionSecretCreate,
			PermissionSecretReadMetadata,
			PermissionSecretWriteVersion,
			PermissionSecretReadHistory,
			PermissionSecretArchive,
			PermissionSecretRestore,
			PermissionServiceTokenCreate,
			PermissionServiceTokenReadMetadata,
			PermissionServiceTokenRevoke,
			PermissionRoleAssignmentRead,
			PermissionRoleAssignmentManage,
			PermissionAuditRead:
			return true
		}
	case RoleProjectAdmin:
		switch permission {
		case PermissionProjectRead,
			PermissionProjectUpdate,
			PermissionProjectArchive,
			PermissionProjectRestore,
			PermissionEnvironmentRead,
			PermissionSecretCreate,
			PermissionSecretReadMetadata,
			PermissionSecretWriteVersion,
			PermissionSecretReadHistory,
			PermissionSecretArchive,
			PermissionSecretRestore,
			PermissionRoleAssignmentRead,
			PermissionAuditRead:
			return true
		}
	case RoleSecretEditor:
		switch permission {
		case PermissionProjectRead,
			PermissionEnvironmentRead,
			PermissionSecretCreate,
			PermissionSecretReadMetadata,
			PermissionSecretWriteVersion,
			PermissionSecretReadHistory,
			PermissionSecretArchive,
			PermissionSecretRestore:
			return true
		}
	case RoleSecretAccessor:
		switch permission {
		case PermissionProjectRead,
			PermissionEnvironmentRead,
			PermissionSecretReadMetadata,
			PermissionSecretReadValue,
			PermissionSecretReadHistory:
			return true
		}
	case RoleAuditor:
		switch permission {
		case PermissionProjectRead,
			PermissionEnvironmentRead,
			PermissionSecretReadMetadata,
			PermissionSecretReadHistory,
			PermissionServiceTokenReadMetadata,
			PermissionRoleAssignmentRead,
			PermissionAuditRead:
			return true
		}
	}

	return false
}

func permissionTarget(permission Permission) ResourceKind {
	switch permission {
	case PermissionProjectCreate:
		return ResourceTenant
	case PermissionProjectRead,
		PermissionProjectUpdate,
		PermissionProjectArchive,
		PermissionProjectRestore:
		return ResourceProject
	case PermissionEnvironmentRead:
		return ResourceEnvironment
	case PermissionSecretCreate,
		PermissionSecretReadMetadata,
		PermissionSecretWriteVersion,
		PermissionSecretReadValue,
		PermissionSecretReadHistory,
		PermissionSecretArchive,
		PermissionSecretRestore:
		return ResourceSecret
	case PermissionServiceTokenCreate,
		PermissionServiceTokenReadMetadata,
		PermissionServiceTokenRevoke:
		return ResourceServiceToken
	case PermissionRoleAssignmentRead,
		PermissionRoleAssignmentManage:
		return ResourceRoleAssignment
	case PermissionAuditRead:
		return ResourceAudit
	default:
		return 0
	}
}

func lifecycleAllows(permission Permission, state ResourceState) bool {
	if state == ResourceParentArchived {
		return false
	}

	switch permission {
	case PermissionProjectRestore, PermissionSecretRestore:
		return state == ResourceArchived
	default:
		return state == ResourceActive
	}
}
