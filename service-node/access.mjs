export function decideAccess({
  identity,
  application,
  assignments,
  requiredPermission,
  scopeType = null,
  scopeId = null,
  satisfiedConditions = [],
  now = new Date(),
}) {
  if (identity.status !== "active") {
    return { allowed: false, reasonCode: "identity_not_active" };
  }
  if (application.status !== "active") {
    return { allowed: false, reasonCode: "application_not_active" };
  }

  let matchingApplication = false;
  let matchingPermission = false;
  let matchingScope = false;
  let matchingConditions = false;
  const conditions = new Set(satisfiedConditions);

  for (const assignment of assignments) {
    if (assignment.subjectId !== identity.identityId) continue;
    if (assignment.applicationId !== application.applicationId) continue;
    matchingApplication = true;
    if (assignment.status !== "active") continue;
    if (assignment.validFrom && now < new Date(assignment.validFrom)) continue;
    if (assignment.validUntil && now >= new Date(assignment.validUntil)) continue;
    if (!assignment.permissions.includes(requiredPermission)) continue;
    matchingPermission = true;
    const exactScope = assignment.scopeType === scopeType && assignment.scopeId === scopeId;
    const globalScope = assignment.scopeType === null && assignment.scopeId === null;
    if (!exactScope && !globalScope) continue;
    matchingScope = true;
    if (!assignment.conditions.every((condition) => conditions.has(condition))) continue;
    matchingConditions = true;
    return { allowed: true, reasonCode: "access_granted", assignment };
  }

  if (!matchingApplication) return { allowed: false, reasonCode: "assignment_missing" };
  if (!matchingPermission) return { allowed: false, reasonCode: "permission_or_validity_missing" };
  if (!matchingScope) return { allowed: false, reasonCode: "scope_mismatch" };
  if (!matchingConditions) return { allowed: false, reasonCode: "conditions_not_satisfied" };
  return { allowed: false, reasonCode: "access_denied" };
}
