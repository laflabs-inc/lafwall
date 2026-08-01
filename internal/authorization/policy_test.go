package authorization

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

const (
	testTenantA      = "tenant-a"
	testTenantB      = "tenant-b"
	testProjectA     = "project-a"
	testProjectB     = "project-b"
	testEnvironmentA = "environment-a"
	testEnvironmentB = "environment-b"
)

func TestRolePermissionMatrixContract(t *testing.T) {
	t.Parallel()

	expected := map[Role][]Permission{
		RoleTenantAdmin: {
			PermissionProjectCreate,
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
			PermissionAuditRead,
		},
		RoleProjectAdmin: {
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
			PermissionRoleAssignmentRead,
			PermissionAuditRead,
		},
		RoleSecretEditor: {
			PermissionProjectRead,
			PermissionEnvironmentRead,
			PermissionSecretCreate,
			PermissionSecretReadMetadata,
			PermissionSecretWriteVersion,
			PermissionSecretReadHistory,
			PermissionSecretArchive,
			PermissionSecretRestore,
		},
		RoleSecretAccessor: {
			PermissionProjectRead,
			PermissionEnvironmentRead,
			PermissionSecretReadMetadata,
			PermissionSecretReadValue,
			PermissionSecretReadHistory,
		},
		RoleAuditor: {
			PermissionProjectRead,
			PermissionEnvironmentRead,
			PermissionSecretReadMetadata,
			PermissionSecretReadHistory,
			PermissionServiceTokenReadMetadata,
			PermissionRoleAssignmentRead,
			PermissionAuditRead,
		},
	}

	roles := KnownRoles()
	permissions := KnownPermissions()
	if len(roles) != 5 {
		t.Fatalf("KnownRoles() length = %d, want 5", len(roles))
	}
	if len(permissions) != 19 {
		t.Fatalf("KnownPermissions() length = %d, want 19", len(permissions))
	}
	assertUnique(t, roles)
	assertUnique(t, permissions)

	for _, role := range roles {
		want := expected[role]
		got := PermissionsForRole(role)
		if !slices.Equal(got, want) {
			t.Fatalf("PermissionsForRole(%q) = %v, want %v", role, got, want)
		}

		principal := mustHuman(t, testTenantA, "principal-matrix")
		assignment := mustAssignment(
			t,
			principal,
			role,
			matrixAssignmentScope(t, role),
		)
		for _, permission := range permissions {
			target := matrixTarget(t, role, permission)
			decision, err := (Policy{}).Authorize(
				principal,
				permission,
				target,
				[]Assignment{assignment},
			)
			wantAllowed := slices.Contains(want, permission)
			if wantAllowed && (err != nil || !decision.Allowed()) {
				t.Fatalf("%q must allow %q: decision=%v error=%v", role, permission, decision, err)
			}
			if !wantAllowed && (!errors.Is(err, ErrDenied) || decision.Allowed()) {
				t.Fatalf("%q must deny %q: decision=%v error=%v", role, permission, decision, err)
			}
		}
	}

	roles[0] = Role("changed")
	permissions[0] = Permission("changed")
	if KnownRoles()[0] != RoleTenantAdmin ||
		KnownPermissions()[0] != PermissionProjectCreate {
		t.Fatal("known vocabulary slices mutate package policy")
	}
	row := PermissionsForRole(RoleSecretAccessor)
	row[0] = PermissionRoleAssignmentManage
	if PermissionsForRole(RoleSecretAccessor)[0] != PermissionProjectRead {
		t.Fatal("PermissionsForRole returned mutable policy state")
	}
}

func TestAuthorizeScopeInheritanceAndIsolation(t *testing.T) {
	t.Parallel()

	policy := Policy{}
	principal := mustHuman(t, testTenantA, "principal-scope")
	projectScope := mustProjectScope(t, testTenantA, testProjectA)
	projectAssignment := mustAssignment(
		t,
		principal,
		RoleSecretAccessor,
		projectScope,
	)

	assertAllowed(
		t,
		policy,
		principal,
		PermissionProjectRead,
		mustTarget(t, ResourceProject, projectScope, ResourceActive),
		projectAssignment,
	)
	assertAllowed(
		t,
		policy,
		principal,
		PermissionSecretReadValue,
		mustTarget(
			t,
			ResourceSecret,
			mustEnvironmentScope(t, testTenantA, testProjectA, testEnvironmentA),
			ResourceActive,
		),
		projectAssignment,
	)

	deniedTargets := []struct {
		name       string
		permission Permission
		target     Target
	}{
		{
			name:       "sibling project",
			permission: PermissionProjectRead,
			target: mustTarget(
				t,
				ResourceProject,
				mustProjectScope(t, testTenantA, testProjectB),
				ResourceActive,
			),
		},
		{
			name:       "sibling environment",
			permission: PermissionSecretReadValue,
			target: mustTarget(
				t,
				ResourceSecret,
				mustEnvironmentScope(t, testTenantA, testProjectB, testEnvironmentA),
				ResourceActive,
			),
		},
		{
			name:       "cross tenant",
			permission: PermissionSecretReadValue,
			target: mustTarget(
				t,
				ResourceSecret,
				mustEnvironmentScope(t, testTenantB, testProjectA, testEnvironmentA),
				ResourceActive,
			),
		},
	}
	for _, test := range deniedTargets {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertDenied(
				t,
				policy,
				principal,
				test.permission,
				test.target,
				[]Assignment{projectAssignment},
			)
		})
	}

	environmentScope := mustEnvironmentScope(
		t,
		testTenantA,
		testProjectA,
		testEnvironmentA,
	)
	environmentAssignment := mustAssignment(
		t,
		principal,
		RoleSecretAccessor,
		environmentScope,
	)
	assertAllowed(
		t,
		policy,
		principal,
		PermissionSecretReadValue,
		mustTarget(t, ResourceSecret, environmentScope, ResourceActive),
		environmentAssignment,
	)
	assertDenied(
		t,
		policy,
		principal,
		PermissionProjectRead,
		mustTarget(t, ResourceProject, projectScope, ResourceActive),
		[]Assignment{environmentAssignment},
	)
	assertDenied(
		t,
		policy,
		principal,
		PermissionSecretReadValue,
		mustTarget(
			t,
			ResourceSecret,
			mustEnvironmentScope(t, testTenantA, testProjectA, testEnvironmentB),
			ResourceActive,
		),
		[]Assignment{environmentAssignment},
	)
}

func TestAuthorizeFailsClosedForInvalidState(t *testing.T) {
	t.Parallel()

	principal := mustHuman(t, testTenantA, "principal-valid")
	otherPrincipal := mustHuman(t, testTenantA, "principal-other")
	scope := mustEnvironmentScope(t, testTenantA, testProjectA, testEnvironmentA)
	assignment := mustAssignment(t, principal, RoleSecretAccessor, scope)
	otherAssignment := mustAssignment(t, otherPrincipal, RoleSecretAccessor, scope)
	revokedAssignment, err := assignment.Revoke()
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	validTarget := mustTarget(t, ResourceSecret, scope, ResourceActive)
	wrongResourceTarget := mustTarget(
		t,
		ResourceEnvironment,
		scope,
		ResourceActive,
	)
	archivedTarget := mustTarget(t, ResourceSecret, scope, ResourceArchived)
	parentArchivedTarget := mustTarget(
		t,
		ResourceSecret,
		scope,
		ResourceParentArchived,
	)
	malformedRole := assignment
	malformedRole.role = Role("unknown-role")
	malformedStatus := assignment
	malformedStatus.status = 0

	tests := map[string]struct {
		principal   Principal
		permission  Permission
		target      Target
		assignments []Assignment
	}{
		"anonymous zero principal": {
			permission:  PermissionSecretReadValue,
			target:      validTarget,
			assignments: []Assignment{assignment},
		},
		"unknown action": {
			principal:   principal,
			permission:  Permission("secret:unknown"),
			target:      validTarget,
			assignments: []Assignment{assignment},
		},
		"unresolved lineage": {
			principal:   principal,
			permission:  PermissionSecretReadValue,
			assignments: []Assignment{assignment},
		},
		"missing assignment": {
			principal:  principal,
			permission: PermissionSecretReadValue,
			target:     validTarget,
		},
		"revoked assignment": {
			principal:   principal,
			permission:  PermissionSecretReadValue,
			target:      validTarget,
			assignments: []Assignment{revokedAssignment},
		},
		"other principal assignment": {
			principal:   principal,
			permission:  PermissionSecretReadValue,
			target:      validTarget,
			assignments: []Assignment{otherAssignment},
		},
		"valid and unrelated assignment mixture": {
			principal:   principal,
			permission:  PermissionSecretReadValue,
			target:      validTarget,
			assignments: []Assignment{assignment, otherAssignment},
		},
		"unknown role": {
			principal:   principal,
			permission:  PermissionSecretReadValue,
			target:      validTarget,
			assignments: []Assignment{assignment, malformedRole},
		},
		"unknown assignment status": {
			principal:   principal,
			permission:  PermissionSecretReadValue,
			target:      validTarget,
			assignments: []Assignment{assignment, malformedStatus},
		},
		"wrong resource kind": {
			principal:   principal,
			permission:  PermissionSecretReadValue,
			target:      wrongResourceTarget,
			assignments: []Assignment{assignment},
		},
		"archived resource": {
			principal:   principal,
			permission:  PermissionSecretReadValue,
			target:      archivedTarget,
			assignments: []Assignment{assignment},
		},
		"archived parent": {
			principal:   principal,
			permission:  PermissionSecretReadValue,
			target:      parentArchivedTarget,
			assignments: []Assignment{assignment},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assertDenied(
				t,
				Policy{},
				test.principal,
				test.permission,
				test.target,
				test.assignments,
			)
		})
	}
}

func TestAuthorizationLifecyclePreconditions(t *testing.T) {
	t.Parallel()

	principal := mustHuman(t, testTenantA, "principal-lifecycle")
	projectScope := mustProjectScope(t, testTenantA, testProjectA)
	assignment := mustAssignment(
		t,
		principal,
		RoleProjectAdmin,
		projectScope,
	)
	policy := Policy{}

	assertAllowed(
		t,
		policy,
		principal,
		PermissionProjectRestore,
		mustTarget(t, ResourceProject, projectScope, ResourceArchived),
		assignment,
	)
	assertDenied(
		t,
		policy,
		principal,
		PermissionProjectRestore,
		mustTarget(t, ResourceProject, projectScope, ResourceActive),
		[]Assignment{assignment},
	)

	environmentScope := mustEnvironmentScope(
		t,
		testTenantA,
		testProjectA,
		testEnvironmentA,
	)
	assertAllowed(
		t,
		policy,
		principal,
		PermissionSecretRestore,
		mustTarget(t, ResourceSecret, environmentScope, ResourceArchived),
		assignment,
	)
	assertDenied(
		t,
		policy,
		principal,
		PermissionSecretRestore,
		mustTarget(
			t,
			ResourceSecret,
			environmentScope,
			ResourceParentArchived,
		),
		[]Assignment{assignment},
	)
}

func TestAssignmentsUnionOnlyExplicitPermissions(t *testing.T) {
	t.Parallel()

	principal := mustHuman(t, testTenantA, "principal-union")
	scope := mustEnvironmentScope(t, testTenantA, testProjectA, testEnvironmentA)
	assignments := []Assignment{
		mustAssignment(t, principal, RoleSecretEditor, scope),
		mustAssignment(t, principal, RoleSecretAccessor, scope),
	}
	secretTarget := mustTarget(t, ResourceSecret, scope, ResourceActive)

	assertAllowed(
		t,
		Policy{},
		principal,
		PermissionSecretWriteVersion,
		secretTarget,
		assignments...,
	)
	assertAllowed(
		t,
		Policy{},
		principal,
		PermissionSecretReadValue,
		secretTarget,
		assignments...,
	)
	assertDenied(
		t,
		Policy{},
		principal,
		PermissionProjectUpdate,
		mustTarget(
			t,
			ResourceProject,
			mustProjectScope(t, testTenantA, testProjectA),
			ResourceActive,
		),
		assignments,
	)
	assertDenied(
		t,
		Policy{},
		principal,
		PermissionRoleAssignmentManage,
		mustTarget(t, ResourceRoleAssignment, scope, ResourceActive),
		assignments,
	)
}

func TestAdministrativeRolesDoNotReadPlaintext(t *testing.T) {
	t.Parallel()

	principal := mustHuman(t, testTenantA, "principal-no-plaintext")
	environmentScope := mustEnvironmentScope(
		t,
		testTenantA,
		testProjectA,
		testEnvironmentA,
	)
	target := mustTarget(t, ResourceSecret, environmentScope, ResourceActive)

	tests := map[Role]Scope{
		RoleTenantAdmin:  mustTenantScope(t, testTenantA),
		RoleProjectAdmin: mustProjectScope(t, testTenantA, testProjectA),
		RoleSecretEditor: environmentScope,
		RoleAuditor:      environmentScope,
	}
	for role, scope := range tests {
		role := role
		scope := scope
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			assignment := mustAssignment(t, principal, role, scope)
			assertDenied(
				t,
				Policy{},
				principal,
				PermissionSecretReadValue,
				target,
				[]Assignment{assignment},
			)
		})
	}
}

func TestSecretAccessorCannotMutate(t *testing.T) {
	t.Parallel()

	principal := mustHuman(t, testTenantA, "principal-read-only")
	scope := mustEnvironmentScope(t, testTenantA, testProjectA, testEnvironmentA)
	assignment := mustAssignment(t, principal, RoleSecretAccessor, scope)
	activeTarget := mustTarget(t, ResourceSecret, scope, ResourceActive)
	archivedTarget := mustTarget(t, ResourceSecret, scope, ResourceArchived)

	tests := map[Permission]Target{
		PermissionSecretCreate:       activeTarget,
		PermissionSecretWriteVersion: activeTarget,
		PermissionSecretArchive:      activeTarget,
		PermissionSecretRestore:      archivedTarget,
	}
	for permission, target := range tests {
		permission := permission
		target := target
		t.Run(string(permission), func(t *testing.T) {
			t.Parallel()
			assertDenied(
				t,
				Policy{},
				principal,
				permission,
				target,
				[]Assignment{assignment},
			)
		})
	}
}

func TestDecisionAndAssignmentAreImmutableSnapshots(t *testing.T) {
	t.Parallel()

	principal := mustHuman(t, testTenantA, "principal-snapshot")
	scope := mustEnvironmentScope(t, testTenantA, testProjectA, testEnvironmentA)
	assignment := mustAssignment(t, principal, RoleSecretAccessor, scope)
	target := mustTarget(t, ResourceSecret, scope, ResourceActive)

	decision, err := (Policy{}).Authorize(
		principal,
		PermissionSecretReadValue,
		target,
		[]Assignment{assignment},
	)
	if err != nil || !decision.Allowed() {
		t.Fatalf("Authorize() decision=%v error=%v, want allowed", decision, err)
	}
	revoked, err := assignment.Revoke()
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if !assignment.Active() || revoked.Active() || !decision.Allowed() {
		t.Fatal("revocation mutated an in-flight assignment or decision value")
	}
	assertDenied(
		t,
		Policy{},
		principal,
		PermissionSecretReadValue,
		target,
		[]Assignment{revoked},
	)
}

func TestAuthorizationFormattingRedactsSensitiveMetadata(t *testing.T) {
	t.Parallel()

	const marker = "sensitive-marker-authorization"
	principal := mustHuman(t, marker+"-tenant", marker+"-principal")
	scope := mustEnvironmentScope(
		t,
		marker+"-tenant",
		marker+"-project",
		marker+"-environment",
	)
	assignment := mustAssignment(t, principal, RoleSecretAccessor, scope)
	target := mustTarget(t, ResourceSecret, scope, ResourceActive)
	decision, err := (Policy{}).Authorize(
		principal,
		PermissionSecretReadValue,
		target,
		[]Assignment{assignment},
	)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	formatted := fmt.Sprintf(
		"%+v %#v %+v %#v %+v %#v %+v %#v",
		principal,
		principal,
		scope,
		scope,
		assignment,
		assignment,
		target,
		decision,
	)
	if strings.Contains(formatted, marker) {
		t.Fatal("routine formatting disclosed authorization metadata")
	}
	if !strings.Contains(formatted, "redacted") {
		t.Fatal("routine formatting does not identify redacted output")
	}
	if strings.Contains(ErrDenied.Error(), marker) ||
		ErrDenied.Error() != "authorization denied" {
		t.Fatal("authorization denial is not sanitized")
	}
}

func TestConstructorsRejectMalformedIdentifiersAndLineage(t *testing.T) {
	t.Parallel()

	invalidIdentifiers := []string{
		"",
		"contains whitespace",
		"non-ascii-☃",
		"line\nbreak",
		strings.Repeat("a", maximumIdentifierBytes+1),
	}
	for _, identifier := range invalidIdentifiers {
		if principal, err := NewHumanPrincipal(testTenantA, identifier); !errors.Is(err, ErrDenied) || principal.Valid() {
			t.Fatalf("NewHumanPrincipal(%q) returned principal=%v error=%v", identifier, principal, err)
		}
		if scope, err := NewTenantScope(identifier); !errors.Is(err, ErrDenied) || scope.Valid() {
			t.Fatalf("NewTenantScope(%q) returned scope=%v error=%v", identifier, scope, err)
		}
	}

	projectScope := mustProjectScope(t, testTenantA, testProjectA)
	if target, err := NewTarget(
		ResourceSecret,
		projectScope,
		ResourceActive,
	); !errors.Is(err, ErrDenied) || target.Valid() {
		t.Fatalf("NewTarget() accepted incompatible lineage: target=%v error=%v", target, err)
	}
	if target, err := NewTarget(
		ResourceKind(255),
		projectScope,
		ResourceActive,
	); !errors.Is(err, ErrDenied) || target.Valid() {
		t.Fatalf("NewTarget() accepted unknown resource: target=%v error=%v", target, err)
	}
}

func matrixAssignmentScope(t *testing.T, role Role) Scope {
	t.Helper()
	switch role {
	case RoleTenantAdmin, RoleAuditor:
		return mustTenantScope(t, testTenantA)
	case RoleProjectAdmin, RoleSecretEditor, RoleSecretAccessor:
		return mustProjectScope(t, testTenantA, testProjectA)
	default:
		t.Fatalf("unknown matrix role %q", role)
		return Scope{}
	}
}

func matrixTarget(t *testing.T, role Role, permission Permission) Target {
	t.Helper()

	kind := permissionTarget(permission)
	state := ResourceActive
	if permission == PermissionProjectRestore || permission == PermissionSecretRestore {
		state = ResourceArchived
	}

	var scope Scope
	switch kind {
	case ResourceTenant, ResourceServiceToken:
		scope = mustTenantScope(t, testTenantA)
	case ResourceProject:
		scope = mustProjectScope(t, testTenantA, testProjectA)
	case ResourceEnvironment, ResourceSecret:
		scope = mustEnvironmentScope(t, testTenantA, testProjectA, testEnvironmentA)
	case ResourceRoleAssignment, ResourceAudit:
		scope = matrixAssignmentScope(t, role)
	default:
		t.Fatalf("unknown target for permission %q", permission)
	}
	return mustTarget(t, kind, scope, state)
}

func assertAllowed(
	t *testing.T,
	policy Policy,
	principal Principal,
	permission Permission,
	target Target,
	assignments ...Assignment,
) {
	t.Helper()
	decision, err := policy.Authorize(
		principal,
		permission,
		target,
		assignments,
	)
	if err != nil || !decision.Allowed() {
		t.Fatalf("Authorize() decision=%v error=%v, want allowed", decision, err)
	}
}

func assertDenied(
	t *testing.T,
	policy Policy,
	principal Principal,
	permission Permission,
	target Target,
	assignments []Assignment,
) {
	t.Helper()
	decision, err := policy.Authorize(
		principal,
		permission,
		target,
		assignments,
	)
	if !errors.Is(err, ErrDenied) || decision.Allowed() {
		t.Fatalf("Authorize() decision=%v error=%v, want ErrDenied", decision, err)
	}
	if err.Error() != ErrDenied.Error() {
		t.Fatalf("Authorize() error = %q, want sanitized denial", err)
	}
}

func mustHuman(t *testing.T, tenantID, principalID string) Principal {
	t.Helper()
	principal, err := NewHumanPrincipal(tenantID, principalID)
	if err != nil {
		t.Fatalf("NewHumanPrincipal() error = %v", err)
	}
	return principal
}

func mustService(t *testing.T, tenantID, principalID string) Principal {
	t.Helper()
	principal, err := NewServicePrincipal(tenantID, principalID)
	if err != nil {
		t.Fatalf("NewServicePrincipal() error = %v", err)
	}
	return principal
}

func mustTenantScope(t *testing.T, tenantID string) Scope {
	t.Helper()
	scope, err := NewTenantScope(tenantID)
	if err != nil {
		t.Fatalf("NewTenantScope() error = %v", err)
	}
	return scope
}

func mustProjectScope(t *testing.T, tenantID, projectID string) Scope {
	t.Helper()
	scope, err := NewProjectScope(tenantID, projectID)
	if err != nil {
		t.Fatalf("NewProjectScope() error = %v", err)
	}
	return scope
}

func mustEnvironmentScope(
	t *testing.T,
	tenantID,
	projectID,
	environmentID string,
) Scope {
	t.Helper()
	scope, err := NewEnvironmentScope(tenantID, projectID, environmentID)
	if err != nil {
		t.Fatalf("NewEnvironmentScope() error = %v", err)
	}
	return scope
}

func mustAssignment(
	t *testing.T,
	principal Principal,
	role Role,
	scope Scope,
) Assignment {
	t.Helper()
	assignment, err := NewAssignment(principal, role, scope)
	if err != nil {
		t.Fatalf("NewAssignment() error = %v", err)
	}
	return assignment
}

func mustTarget(
	t *testing.T,
	kind ResourceKind,
	scope Scope,
	state ResourceState,
) Target {
	t.Helper()
	target, err := NewTarget(kind, scope, state)
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}
	return target
}

func assertUnique[T comparable](t *testing.T, values []T) {
	t.Helper()
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			t.Fatalf("duplicate contract value %v", value)
		}
		seen[value] = struct{}{}
	}
}
