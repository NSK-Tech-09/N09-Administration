import { decideAccess } from "./access.mjs";
import { ADMIN_APPLICATION_ID } from "./identity-link-admin.mjs";

export const NOTIFICATION_OPERATIONS_READ_PERMISSION = "administration:notifications:read";

export async function authorizeNotificationOperationsAdministration(repository, identityId, now = new Date()) {
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
    requiredPermission: NOTIFICATION_OPERATIONS_READ_PERMISSION,
    scopeType: null,
    scopeId: null,
    now,
  });
}
