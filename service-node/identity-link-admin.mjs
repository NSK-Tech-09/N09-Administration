import { decideAccess } from "./access.mjs";

export const ADMIN_APPLICATION_ID = "n09-administration";
export const LINK_DECISION_PERMISSION = "administration:identity-links:decide";

export async function authorizeIdentityLinkAdministration(repository, identityId, now = new Date()) {
  if (typeof identityId !== "string" || !identityId) {
    return { allowed: false, reasonCode: "authentication_required" };
  }
  const [identity, application, assignments] = await Promise.all([
    repository.getIdentity(identityId),
    repository.getApplication(ADMIN_APPLICATION_ID),
    repository.listAssignments(identityId, ADMIN_APPLICATION_ID),
  ]);
  if (!identity || !application) return { allowed: false, reasonCode: "administration_not_configured" };
  return decideAccess({
    identity,
    application,
    assignments,
    requiredPermission: LINK_DECISION_PERMISSION,
    scopeType: null,
    scopeId: null,
    now,
  });
}
