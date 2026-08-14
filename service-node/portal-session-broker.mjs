import { evaluateAccessRequestAsync } from "./api.mjs";
import { open, seal } from "./oidc.mjs";

export const PORTAL_APPLICATION_ID = "n09-portail";
export const PORTAL_PERMISSION = "portal:read";
export const PORTAL_SESSION_COOKIE = "n09_portal_session";
export const PORTAL_SESSION_PURPOSE = "portal-application-session";

function exactHttpsOrigin(value) {
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" ||
      parsed.search || parsed.hash) throw new Error("invalid portal origin");
  return parsed.origin;
}

export function portalOriginsFromEnvironment(environment = process.env) {
  const raw = environment.N09_PORTAL_ORIGINS?.trim();
  if (!raw) return Object.freeze([]);
  const origins = [...new Set(raw.split(",").map((value) => exactHttpsOrigin(value.trim())))];
  if (!origins.length) throw new Error("at least one portal origin is required");
  return Object.freeze(origins);
}

export function safePortalReturn(value, allowedOrigins, fallback = null) {
  if (typeof value !== "string" || /[\r\n]/.test(value)) return fallback;
  try {
    const parsed = new URL(value);
    if (!allowedOrigins.includes(parsed.origin) || parsed.username || parsed.password) return fallback;
    return parsed.toString();
  } catch {
    return fallback;
  }
}

export async function issuePortalSession({ repository, sessionAuthority, identitySession, sessionSecret, now = Date.now() }) {
  if (identitySession?.status !== "authenticated" || !identitySession.identityId) {
    throw new Error("portal_identity_session_required");
  }
  const decision = await evaluateAccessRequestAsync({
    repository,
    principal: { applicationId: PORTAL_APPLICATION_ID, audience: PORTAL_APPLICATION_ID },
    payload: {
      identity_id: identitySession.identityId,
      application_id: PORTAL_APPLICATION_ID,
      required_permission: PORTAL_PERMISSION,
      satisfied_conditions: [],
    },
  });
  if (decision.status !== 200 || decision.body.allowed !== true) throw new Error("portal_access_denied");
  const identity = await repository.getIdentity(identitySession.identityId);
  if (!identity || identity.status !== "active") throw new Error("portal_identity_inactive");
  const issued = await sessionAuthority?.issue({
    identityId: identitySession.identityId,
    applicationId: PORTAL_APPLICATION_ID,
    authenticatedAt: new Date(now),
  });
  if (!issued?.credential) throw new Error("portal_session_authority_unavailable");
  const expiresAt = Math.min(now + 4 * 60 * 60_000, Date.parse(issued.absoluteExpiresAt));
  if (!Number.isFinite(expiresAt) || expiresAt <= now) throw new Error("portal_session_invalid");
  return seal({
    version: 1,
    identityId: identitySession.identityId,
    displayName: identity.displayName,
    email: identity.email,
    credential: issued.credential,
    expiresAt,
  }, sessionSecret, PORTAL_SESSION_PURPOSE);
}

export function openPortalSession(value, sessionSecret, now = Date.now()) {
  const session = open(value, sessionSecret, PORTAL_SESSION_PURPOSE, now);
  if (session.version !== 1 || typeof session.identityId !== "string" ||
      typeof session.credential?.sessionId !== "string" || typeof session.credential?.secret !== "string") {
    throw new Error("portal_session_invalid");
  }
  return session;
}

function assignmentIsCurrent(assignment, now) {
  if (assignment.status !== "active" || (assignment.conditions?.length ?? 0) !== 0) return false;
  const current = new Date(now).valueOf();
  const starts = assignment.validFrom ? new Date(assignment.validFrom).valueOf() : -Infinity;
  const ends = assignment.validUntil ? new Date(assignment.validUntil).valueOf() : Infinity;
  return Number.isFinite(current) && starts <= current && current < ends;
}

export async function portalDirectory({ repository, sessionAuthority, session, now = new Date() }) {
  const assessment = await sessionAuthority?.assess({
    credential: session.credential,
    identityId: session.identityId,
    applicationId: PORTAL_APPLICATION_ID,
  });
  if (!assessment?.allowed) throw new Error(assessment?.reasonCode || "portal_session_rejected");
  const [identity, applications, assignments] = await Promise.all([
    repository.getIdentity(session.identityId),
    repository.listApplications(),
    repository.listAllAssignments(),
  ]);
  if (!identity || identity.status !== "active") throw new Error("portal_identity_inactive");
  const activeApplicationIds = new Set(applications
    .filter((application) => application.status === "active")
    .map((application) => application.applicationId));
  const allowed = [...new Set(assignments
    .filter((assignment) => assignment.subjectId === session.identityId && assignmentIsCurrent(assignment, now))
    .map((assignment) => assignment.applicationId)
    .filter((applicationId) => applicationId !== PORTAL_APPLICATION_ID && activeApplicationIds.has(applicationId)))]
    .sort();
  return Object.freeze({
    identity: Object.freeze({ identityId: identity.identityId, displayName: identity.displayName, email: identity.email }),
    applications: Object.freeze(allowed),
  });
}

export async function revokePortalSession({ sessionAuthority, session }) {
  const result = await sessionAuthority?.revokeForApplication({
    sessionId: session.credential.sessionId,
    identityId: session.identityId,
    applicationId: PORTAL_APPLICATION_ID,
    reason: "Déconnexion demandée depuis le portail NSK Tech 09",
  });
  if (!result?.revoked) throw new Error(result?.reasonCode || "portal_revocation_unconfirmed");
  return result;
}
