package authorization

// Grant validates one immutable Role assignment against a complete,
// authoritative Tenant assignment snapshot. It returns the proposed value but
// performs no persistence or audit write. A future application transaction
// must commit both atomically.
func (policy Policy) Grant(
	actor Principal,
	recipient Principal,
	role Role,
	scope Scope,
	tenantAssignments []Assignment,
) (Assignment, error) {
	if !actor.Valid() ||
		!recipient.Valid() ||
		actor.tenantID != recipient.tenantID ||
		actor.tenantID != scope.tenantID {
		return Assignment{}, ErrDenied
	}

	proposed, err := NewAssignment(recipient, role, scope)
	if err != nil {
		return Assignment{}, ErrDenied
	}

	actorAssignments, ok := assignmentsForPrincipal(
		actor,
		tenantAssignments,
	)
	if !ok {
		return Assignment{}, ErrDenied
	}
	target, err := NewTarget(
		ResourceRoleAssignment,
		scope,
		ResourceActive,
	)
	if err != nil {
		return Assignment{}, ErrDenied
	}
	if _, err := policy.Authorize(
		actor,
		PermissionRoleAssignmentManage,
		target,
		actorAssignments,
	); err != nil {
		return Assignment{}, ErrDenied
	}

	return proposed, nil
}

// Revoke validates an immutable assignment revocation against a complete,
// authoritative Tenant assignment snapshot. It refuses to remove the last
// distinct active Human tenant_admin and performs no persistence or audit I/O.
func (policy Policy) Revoke(
	actor Principal,
	targetAssignment Assignment,
	tenantAssignments []Assignment,
) (Assignment, error) {
	if !actor.Valid() || !targetAssignment.Active() {
		return Assignment{}, ErrDenied
	}

	actorAssignments, ok := assignmentsForPrincipal(
		actor,
		tenantAssignments,
	)
	if !ok || !containsAssignment(tenantAssignments, targetAssignment) {
		return Assignment{}, ErrDenied
	}
	target, err := NewTarget(
		ResourceRoleAssignment,
		targetAssignment.scope,
		ResourceActive,
	)
	if err != nil {
		return Assignment{}, ErrDenied
	}
	if _, err := policy.Authorize(
		actor,
		PermissionRoleAssignmentManage,
		target,
		actorAssignments,
	); err != nil {
		return Assignment{}, ErrDenied
	}

	if targetAssignment.role == RoleTenantAdmin &&
		activeHumanTenantAdministrators(tenantAssignments) <= 1 {
		return Assignment{}, ErrDenied
	}

	revoked, err := targetAssignment.Revoke()
	if err != nil {
		return Assignment{}, ErrDenied
	}
	return revoked, nil
}

func assignmentsForPrincipal(
	principal Principal,
	tenantAssignments []Assignment,
) ([]Assignment, bool) {
	if !principal.Valid() || len(tenantAssignments) == 0 {
		return nil, false
	}

	assignments := make([]Assignment, 0, len(tenantAssignments))
	for _, assignment := range tenantAssignments {
		if !assignment.Valid() ||
			assignment.scope.tenantID != principal.tenantID {
			return nil, false
		}
		if assignment.principal == principal {
			assignments = append(assignments, assignment)
		}
	}
	return assignments, len(assignments) > 0
}

func containsAssignment(
	assignments []Assignment,
	target Assignment,
) bool {
	for _, assignment := range assignments {
		if assignment == target {
			return true
		}
	}
	return false
}

func activeHumanTenantAdministrators(assignments []Assignment) int {
	principals := make(map[string]struct{})
	for _, assignment := range assignments {
		if assignment.Active() &&
			assignment.principal.kind == PrincipalHuman &&
			assignment.role == RoleTenantAdmin &&
			assignment.scope.kind == ScopeTenant {
			principals[assignment.principal.principalID] = struct{}{}
		}
	}
	return len(principals)
}
