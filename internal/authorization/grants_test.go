package authorization

import (
	"errors"
	"testing"
)

func TestAssignmentPrincipalAndScopeEligibility(t *testing.T) {
	t.Parallel()

	human := mustHuman(t, testTenantA, "human-eligibility")
	service := mustService(t, testTenantA, "service-eligibility")
	tenantScope := mustTenantScope(t, testTenantA)
	projectScope := mustProjectScope(t, testTenantA, testProjectA)
	environmentScope := mustEnvironmentScope(
		t,
		testTenantA,
		testProjectA,
		testEnvironmentA,
	)

	allowed := []struct {
		principal Principal
		role      Role
		scope     Scope
	}{
		{human, RoleTenantAdmin, tenantScope},
		{human, RoleProjectAdmin, projectScope},
		{human, RoleSecretEditor, projectScope},
		{human, RoleSecretEditor, environmentScope},
		{human, RoleSecretAccessor, projectScope},
		{human, RoleSecretAccessor, environmentScope},
		{human, RoleAuditor, tenantScope},
		{human, RoleAuditor, projectScope},
		{human, RoleAuditor, environmentScope},
		{service, RoleSecretEditor, projectScope},
		{service, RoleSecretEditor, environmentScope},
		{service, RoleSecretAccessor, projectScope},
		{service, RoleSecretAccessor, environmentScope},
	}
	for _, test := range allowed {
		assignment, err := NewAssignment(test.principal, test.role, test.scope)
		if err != nil || !assignment.Active() {
			t.Fatalf(
				"NewAssignment(kind=%v, role=%q, scope=%v) assignment=%v error=%v",
				test.principal.Kind(),
				test.role,
				test.scope.Kind(),
				assignment,
				err,
			)
		}
	}

	denied := []struct {
		principal Principal
		role      Role
		scope     Scope
	}{
		{human, RoleTenantAdmin, projectScope},
		{human, RoleProjectAdmin, tenantScope},
		{human, RoleProjectAdmin, environmentScope},
		{human, RoleSecretEditor, tenantScope},
		{human, RoleSecretAccessor, tenantScope},
		{service, RoleTenantAdmin, tenantScope},
		{service, RoleProjectAdmin, projectScope},
		{service, RoleAuditor, environmentScope},
		{service, RoleSecretEditor, tenantScope},
		{service, RoleSecretAccessor, tenantScope},
		{human, Role("custom-role"), tenantScope},
	}
	for _, test := range denied {
		assignment, err := NewAssignment(test.principal, test.role, test.scope)
		if !errors.Is(err, ErrDenied) || assignment.Valid() {
			t.Fatalf(
				"NewAssignment(kind=%v, role=%q, scope=%v) assignment=%v error=%v, want denial",
				test.principal.Kind(),
				test.role,
				test.scope.Kind(),
				assignment,
				err,
			)
		}
	}
}

func TestServicePrincipalAuthorizationIsRoleAndTenantBound(t *testing.T) {
	t.Parallel()

	service := mustService(t, testTenantA, "service-policy")
	scope := mustEnvironmentScope(t, testTenantA, testProjectA, testEnvironmentA)
	editor := mustAssignment(t, service, RoleSecretEditor, scope)
	accessor := mustAssignment(t, service, RoleSecretAccessor, scope)
	target := mustTarget(t, ResourceSecret, scope, ResourceActive)

	assertAllowed(
		t,
		Policy{},
		service,
		PermissionSecretWriteVersion,
		target,
		editor,
	)
	assertAllowed(
		t,
		Policy{},
		service,
		PermissionSecretReadValue,
		target,
		accessor,
	)
	assertDenied(
		t,
		Policy{},
		service,
		PermissionSecretReadValue,
		target,
		[]Assignment{editor},
	)
	assertDenied(
		t,
		Policy{},
		service,
		PermissionSecretReadValue,
		mustTarget(
			t,
			ResourceSecret,
			mustEnvironmentScope(t, testTenantB, testProjectA, testEnvironmentA),
			ResourceActive,
		),
		[]Assignment{accessor},
	)
}

func TestTenantAdministratorGrantRules(t *testing.T) {
	t.Parallel()

	policy := Policy{}
	actor := mustHuman(t, testTenantA, "human-admin")
	actorAssignment := mustAssignment(
		t,
		actor,
		RoleTenantAdmin,
		mustTenantScope(t, testTenantA),
	)
	humanRecipient := mustHuman(t, testTenantA, "human-recipient")
	serviceRecipient := mustService(t, testTenantA, "service-recipient")

	allowed := []struct {
		recipient Principal
		role      Role
		scope     Scope
	}{
		{humanRecipient, RoleTenantAdmin, mustTenantScope(t, testTenantA)},
		{humanRecipient, RoleProjectAdmin, mustProjectScope(t, testTenantA, testProjectA)},
		{humanRecipient, RoleSecretEditor, mustProjectScope(t, testTenantA, testProjectA)},
		{humanRecipient, RoleSecretAccessor, mustEnvironmentScope(t, testTenantA, testProjectA, testEnvironmentA)},
		{humanRecipient, RoleAuditor, mustTenantScope(t, testTenantA)},
		{serviceRecipient, RoleSecretEditor, mustProjectScope(t, testTenantA, testProjectA)},
		{serviceRecipient, RoleSecretAccessor, mustEnvironmentScope(t, testTenantA, testProjectA, testEnvironmentA)},
	}
	for _, test := range allowed {
		assignment, err := policy.Grant(
			actor,
			test.recipient,
			test.role,
			test.scope,
			[]Assignment{actorAssignment},
		)
		if err != nil || !assignment.Active() ||
			assignment.Principal() != test.recipient ||
			assignment.Role() != test.role ||
			assignment.Scope() != test.scope {
			t.Fatalf("Grant(role=%q) assignment=%v error=%v", test.role, assignment, err)
		}
	}

	denied := []struct {
		recipient Principal
		role      Role
		scope     Scope
	}{
		{serviceRecipient, RoleTenantAdmin, mustTenantScope(t, testTenantA)},
		{serviceRecipient, RoleProjectAdmin, mustProjectScope(t, testTenantA, testProjectA)},
		{serviceRecipient, RoleAuditor, mustEnvironmentScope(t, testTenantA, testProjectA, testEnvironmentA)},
		{humanRecipient, RoleTenantAdmin, mustProjectScope(t, testTenantA, testProjectA)},
		{humanRecipient, RoleProjectAdmin, mustEnvironmentScope(t, testTenantA, testProjectA, testEnvironmentA)},
		{humanRecipient, RoleSecretEditor, mustTenantScope(t, testTenantA)},
		{humanRecipient, Role("custom-role"), mustTenantScope(t, testTenantA)},
		{mustHuman(t, testTenantB, "human-other-tenant"), RoleAuditor, mustTenantScope(t, testTenantA)},
	}
	for _, test := range denied {
		assignment, err := policy.Grant(
			actor,
			test.recipient,
			test.role,
			test.scope,
			[]Assignment{actorAssignment},
		)
		if !errors.Is(err, ErrDenied) || assignment.Valid() {
			t.Fatalf("Grant(role=%q) assignment=%v error=%v, want denial", test.role, assignment, err)
		}
	}
}

func TestGrantDeniesNonAdministratorAndMalformedSnapshot(t *testing.T) {
	t.Parallel()

	actor := mustHuman(t, testTenantA, "human-project-admin")
	projectScope := mustProjectScope(t, testTenantA, testProjectA)
	projectAssignment := mustAssignment(
		t,
		actor,
		RoleProjectAdmin,
		projectScope,
	)
	recipient := mustHuman(t, testTenantA, "human-grant-recipient")

	assignment, err := (Policy{}).Grant(
		actor,
		recipient,
		RoleSecretAccessor,
		projectScope,
		[]Assignment{projectAssignment},
	)
	if !errors.Is(err, ErrDenied) || assignment.Valid() {
		t.Fatalf("project administrator Grant() assignment=%v error=%v", assignment, err)
	}

	tenantAdmin := mustAssignment(
		t,
		actor,
		RoleTenantAdmin,
		mustTenantScope(t, testTenantA),
	)
	malformed := projectAssignment
	malformed.role = Role("unknown-role")
	assignment, err = (Policy{}).Grant(
		actor,
		recipient,
		RoleSecretAccessor,
		projectScope,
		[]Assignment{tenantAdmin, malformed},
	)
	if !errors.Is(err, ErrDenied) || assignment.Valid() {
		t.Fatalf("malformed snapshot Grant() assignment=%v error=%v", assignment, err)
	}
}

func TestRevokeProtectsLastDistinctHumanTenantAdministrator(t *testing.T) {
	t.Parallel()

	policy := Policy{}
	firstAdmin := mustHuman(t, testTenantA, "human-admin-first")
	firstAssignment := mustAssignment(
		t,
		firstAdmin,
		RoleTenantAdmin,
		mustTenantScope(t, testTenantA),
	)

	revoked, err := policy.Revoke(
		firstAdmin,
		firstAssignment,
		[]Assignment{firstAssignment},
	)
	if !errors.Is(err, ErrDenied) || revoked.Valid() {
		t.Fatalf("last admin Revoke() assignment=%v error=%v", revoked, err)
	}
	revoked, err = policy.Revoke(
		firstAdmin,
		firstAssignment,
		[]Assignment{firstAssignment, firstAssignment},
	)
	if !errors.Is(err, ErrDenied) || revoked.Valid() {
		t.Fatalf("duplicate last admin Revoke() assignment=%v error=%v", revoked, err)
	}

	secondAdmin := mustHuman(t, testTenantA, "human-admin-second")
	secondAssignment := mustAssignment(
		t,
		secondAdmin,
		RoleTenantAdmin,
		mustTenantScope(t, testTenantA),
	)
	snapshot := []Assignment{firstAssignment, secondAssignment}
	revoked, err = policy.Revoke(firstAdmin, firstAssignment, snapshot)
	if err != nil || revoked.Status() != AssignmentRevoked || revoked.Active() {
		t.Fatalf("Revoke() assignment=%v error=%v", revoked, err)
	}
	if !firstAssignment.Active() || !snapshot[0].Active() {
		t.Fatal("Revoke() mutated the target or authoritative snapshot")
	}
}

func TestRevokeRequiresAuthorizedActorAndExactSnapshotTarget(t *testing.T) {
	t.Parallel()

	admin := mustHuman(t, testTenantA, "human-revoke-admin")
	adminAssignment := mustAssignment(
		t,
		admin,
		RoleTenantAdmin,
		mustTenantScope(t, testTenantA),
	)
	recipient := mustHuman(t, testTenantA, "human-revoke-recipient")
	target := mustAssignment(
		t,
		recipient,
		RoleSecretAccessor,
		mustProjectScope(t, testTenantA, testProjectA),
	)

	if revoked, err := (Policy{}).Revoke(
		admin,
		target,
		[]Assignment{adminAssignment},
	); !errors.Is(err, ErrDenied) || revoked.Valid() {
		t.Fatalf("missing target Revoke() assignment=%v error=%v", revoked, err)
	}

	nonAdmin := mustHuman(t, testTenantA, "human-revoke-non-admin")
	nonAdminAssignment := mustAssignment(
		t,
		nonAdmin,
		RoleProjectAdmin,
		mustProjectScope(t, testTenantA, testProjectA),
	)
	if revoked, err := (Policy{}).Revoke(
		nonAdmin,
		target,
		[]Assignment{nonAdminAssignment, target},
	); !errors.Is(err, ErrDenied) || revoked.Valid() {
		t.Fatalf("non-admin Revoke() assignment=%v error=%v", revoked, err)
	}

	malformed := target
	malformed.status = 0
	if revoked, err := (Policy{}).Revoke(
		admin,
		target,
		[]Assignment{adminAssignment, target, malformed},
	); !errors.Is(err, ErrDenied) || revoked.Valid() {
		t.Fatalf("malformed snapshot Revoke() assignment=%v error=%v", revoked, err)
	}

	revoked, err := (Policy{}).Revoke(
		admin,
		target,
		[]Assignment{adminAssignment, target},
	)
	if err != nil || revoked.Status() != AssignmentRevoked {
		t.Fatalf("authorized Revoke() assignment=%v error=%v", revoked, err)
	}
}
