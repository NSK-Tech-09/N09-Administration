import { decideAccess } from "./access.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";

export const ACCESS_DIRECTORY_READ_PERMISSION = "administration:access:read";

export async function authorizeAccessAdministration(repository, identityId, now = new Date()) {
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
    requiredPermission: ACCESS_DIRECTORY_READ_PERMISSION,
    scopeType: null,
    scopeId: null,
    now,
  });
}
