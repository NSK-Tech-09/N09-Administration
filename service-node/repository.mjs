import { randomUUID } from "node:crypto";
import { eventHash, verifyAuditChain } from "./audit.mjs";
import {
  assertApplicationSessionActivityProgress,
  assertApplicationSessionAudit,
  assertApplicationSessionImmutableContext,
  assertNewApplicationSessionRecord,
} from "./application-session.mjs";
import {
  ApplicationAccessCatalogError, applicationAccessCatalogHash, assertCompatibleCatalogEvolution,
} from "./application-access-catalog.mjs";
import { NotificationIngressError } from "./notification-ingress.mjs";

function cloneMap(map) {
  return new Map([...map].map(([key, value]) => [key, structuredClone(value)]));
}

function accessRequestStatus(lines) {
  const statuses = new Set(lines.map((line) => line.status));
  if (statuses.has("pending")) return "pending";
  if (statuses.size === 1 && statuses.has("approved")) return "approved";
  if (statuses.size === 1 && statuses.has("refused")) return "refused";
  return "partially_approved";
}

function stateApplicationName(applications, applicationId) {
  return applications.get(applicationId)?.displayName ?? applicationId;
}

export class TransactionalMemoryRepository {
  #identities = new Map();
  #externalIdentities = new Map();
  #linkRequests = new Map();
  #applications = new Map();
  #applicationAccessCatalogs = new Map();
  #applicationRedirectUris = new Map();
  #applicationLoginPolicies = new Map();
  #applicationAuthorizationCodes = new Map();
  #applicationSessions = new Map();
  #assignments = new Map();
  #accessRequests = new Map();
  #accessRequestLines = new Map();
  #notificationEvents = new Map();
  #emailLoginTokens = new Map();
  #auditEntries = [];

  #transaction(operation) {
    const state = {
      identities: cloneMap(this.#identities),
      externalIdentities: cloneMap(this.#externalIdentities),
      linkRequests: cloneMap(this.#linkRequests),
      applications: cloneMap(this.#applications),
      applicationAccessCatalogs: cloneMap(this.#applicationAccessCatalogs),
      applicationRedirectUris: cloneMap(this.#applicationRedirectUris),
      applicationLoginPolicies: cloneMap(this.#applicationLoginPolicies),
      applicationAuthorizationCodes: cloneMap(this.#applicationAuthorizationCodes),
      applicationSessions: cloneMap(this.#applicationSessions),
      assignments: cloneMap(this.#assignments),
      accessRequests: cloneMap(this.#accessRequests),
      accessRequestLines: cloneMap(this.#accessRequestLines),
      notificationEvents: cloneMap(this.#notificationEvents),
      emailLoginTokens: cloneMap(this.#emailLoginTokens),
      auditEntries: structuredClone(this.#auditEntries),
    };
    const result = operation(state);
    this.#identities = state.identities;
    this.#externalIdentities = state.externalIdentities;
    this.#linkRequests = state.linkRequests;
    this.#applications = state.applications;
    this.#applicationAccessCatalogs = state.applicationAccessCatalogs;
    this.#applicationRedirectUris = state.applicationRedirectUris;
    this.#applicationLoginPolicies = state.applicationLoginPolicies;
    this.#applicationAuthorizationCodes = state.applicationAuthorizationCodes;
    this.#applicationSessions = state.applicationSessions;
    this.#assignments = state.assignments;
    this.#accessRequests = state.accessRequests;
    this.#accessRequestLines = state.accessRequestLines;
    this.#notificationEvents = state.notificationEvents;
    this.#emailLoginTokens = state.emailLoginTokens;
    this.#auditEntries = state.auditEntries;
    return result;
  }

  #appendAudit(state, auditEvent) {
    const previousHash = state.auditEntries.at(-1)?.eventHash ?? "";
    state.auditEntries.push(Object.freeze({
      sequence: state.auditEntries.length + 1,
      event: auditEvent,
      previousHash,
      eventHash: eventHash(auditEvent, previousHash),
    }));
  }

  saveIdentity(identity, auditEvent) {
    if (auditEvent.subject_id !== identity.identityId) throw new Error("audit subject must match identity");
    return this.#transaction((state) => {
      const previous = state.identities.get(identity.identityId);
      if (previous && !auditEvent.previous_value) throw new Error("previous value is required for update");
      const email = identity.email.trim().toLowerCase();
      if ([...state.identities.values()].some((item) => item.identityId !== identity.identityId && item.email === email)) {
        throw new Error("identity email must be unique");
      }
      state.identities.set(identity.identityId, structuredClone({ ...identity, email }));
      this.#appendAudit(state, auditEvent);
    });
  }

  saveApplication(application, auditEvent) {
    if (auditEvent.application_id !== application.applicationId) throw new Error("audit application must match application");
    return this.#transaction((state) => {
      const previous = state.applications.get(application.applicationId);
      if (previous && !auditEvent.previous_value) throw new Error("previous value is required for update");
      state.applications.set(application.applicationId, structuredClone(application));
      this.#appendAudit(state, auditEvent);
    });
  }

  saveLinkRequest(request, auditEvent) {
    if (request.status !== "pending") throw new Error("a new link request must be pending");
    if (auditEvent.action !== "external_identity.link_requested") throw new Error("invalid audit action for link request");
    return this.#transaction((state) => {
      const principalKey = `${request.issuer}\n${request.subject}`;
      if (state.externalIdentities.has(principalKey)) throw new Error("external identity is already linked");
      const requestedAt = new Date(request.requestedAt);
      const active = [...state.linkRequests.values()].find((item) =>
        item.issuer === request.issuer && item.subject === request.subject &&
        item.status === "pending" && new Date(item.expiresAt) > requestedAt,
      );
      if (active) throw new Error("an active link request already exists");
      state.linkRequests.set(request.requestId, structuredClone(request));
      this.#appendAudit(state, auditEvent);
    });
  }

  getLinkRequest(requestId) {
    return structuredClone(this.#linkRequests.get(requestId) ?? null);
  }

  publishApplicationAccessCatalog(catalog, auditEvent) {
    if (auditEvent.application_id !== catalog.applicationId) throw new Error("audit application must match catalog");
    return this.#transaction((state) => {
      if (!state.applications.has(catalog.applicationId)) throw new Error("application not found");
      const key = `${catalog.applicationId}\n${catalog.catalogVersion}`;
      const existing = state.applicationAccessCatalogs.get(key);
      const catalogHash = applicationAccessCatalogHash(catalog);
      if (existing) {
        if (existing.catalogHash !== catalogHash) throw new ApplicationAccessCatalogError("catalog_version_conflict", 409);
        return { created: false, catalog: structuredClone(existing) };
      }
      const previous = [...state.applicationAccessCatalogs.values()]
        .filter((item) => item.applicationId === catalog.applicationId)
        .sort((left, right) => right.catalogVersion - left.catalogVersion)[0] ?? null;
      assertCompatibleCatalogEvolution(previous, catalog);
      const roleIds = new Set(catalog.roles.map((item) => item.role_id));
      const permissionIds = new Set(catalog.permissions.map((item) => item.permission_id));
      const incompatibleAssignment = [...state.assignments.values()].find((assignment) =>
        assignment.applicationId === catalog.applicationId && assignment.status === "active" &&
        (!roleIds.has(assignment.roleId) || assignment.permissions.some((permission) => !permissionIds.has(permission)))
      );
      if (incompatibleAssignment) throw new ApplicationAccessCatalogError("catalog_excludes_active_assignment", 409);
      const stored = { ...structuredClone(catalog), catalogHash, publishedAt: auditEvent.occurred_at };
      state.applicationAccessCatalogs.set(key, stored);
      this.#appendAudit(state, auditEvent);
      return { created: true, catalog: structuredClone(stored) };
    });
  }

  saveApplicationRedirectUri(applicationId, redirectUri, auditEvent) {
    return this.#transaction((state) => {
      if (!state.applications.has(applicationId)) throw new Error("application not found");
      state.applicationRedirectUris.set(`${applicationId}\n${redirectUri}`, { applicationId, redirectUri, status: "active" });
      this.#appendAudit(state, auditEvent);
    });
  }

  isApplicationRedirectUriAllowed(applicationId, redirectUri) {
    return this.#applicationRedirectUris.get(`${applicationId}\n${redirectUri}`)?.status === "active";
  }

  getApplicationRedirectUri(applicationId, redirectUri) {
    return structuredClone(this.#applicationRedirectUris.get(`${applicationId}\n${redirectUri}`) ?? null);
  }

  saveApplicationLoginPolicy(applicationId, requiredPermission, auditEvent) {
    return this.#transaction((state) => {
      if (!state.applications.has(applicationId)) throw new Error("application not found");
      state.applicationLoginPolicies.set(applicationId, { applicationId, requiredPermission, status: "active" });
      this.#appendAudit(state, auditEvent);
    });
  }

  getApplicationLoginPolicy(applicationId) {
    return structuredClone(this.#applicationLoginPolicies.get(applicationId) ?? null);
  }

  saveApplicationAuthorizationCode(record, auditEvent) {
    return this.#transaction((state) => {
      if (state.applicationAuthorizationCodes.has(record.codeHash)) throw new Error("authorization code already exists");
      state.applicationAuthorizationCodes.set(record.codeHash, structuredClone({ ...record, consumedAt: null }));
      this.#appendAudit(state, auditEvent);
    });
  }

  consumeApplicationAuthorizationCode({ codeHash, applicationId, redirectUri, codeChallenge, now = new Date() }, auditEvent) {
    return this.#transaction((state) => {
      const record = state.applicationAuthorizationCodes.get(codeHash);
      if (!record || record.consumedAt || record.applicationId !== applicationId ||
          record.redirectUri !== redirectUri || record.codeChallenge !== codeChallenge || new Date(record.expiresAt) <= now) return null;
      const consumed = { ...record, consumedAt: now.toISOString() };
      state.applicationAuthorizationCodes.set(codeHash, consumed);
      this.#appendAudit(state, auditEvent);
      return structuredClone(consumed);
    });
  }

  saveApplicationSession(record, auditEvent) {
    assertApplicationSessionAudit(record, auditEvent, "application_session.created");
    assertNewApplicationSessionRecord(record);
    return this.#transaction((state) => {
      if (!state.identities.has(record.identityId) || !state.applications.has(record.applicationId)) {
        throw new Error("application session prerequisites are missing");
      }
      if (state.applicationSessions.has(record.sessionId)) throw new Error("application session already exists");
      if ([...state.applicationSessions.values()].some((item) => item.secretHash === record.secretHash)) {
        throw new Error("application session secret hash must be unique");
      }
      state.applicationSessions.set(record.sessionId, structuredClone(record));
      this.#appendAudit(state, auditEvent);
      return structuredClone(record);
    });
  }

  getApplicationSession(sessionId) {
    return structuredClone(this.#applicationSessions.get(sessionId) ?? null);
  }

  listApplicationSessions(identityId) {
    return [...this.#applicationSessions.values()]
      .filter((item) => item.identityId === identityId)
      .sort((left, right) => String(right.lastSeenAt).localeCompare(String(left.lastSeenAt)))
      .map((item) => structuredClone(item));
  }

  suspendIdentityAndRevokeSessions({ identity, expectedStatus, observedAt, identityAuditEvent, closures }) {
    if (identity.status !== "suspended" || expectedStatus !== "active" ||
        identityAuditEvent?.action !== "identity.suspended" ||
        identityAuditEvent.subject_id !== identity.identityId) {
      throw new Error("invalid identity suspension bundle");
    }
    const decisionTime = new Date(observedAt);
    if (!Number.isFinite(decisionTime.valueOf())) throw new Error("invalid identity suspension time");
    if (!Array.isArray(closures)) throw new Error("application session closures are required");
    if (identityAuditEvent.previous_value?.status !== expectedStatus ||
        identityAuditEvent.new_value?.status !== "suspended" ||
        identityAuditEvent.new_value?.revoked_sessions !== closures.length) {
      throw new Error("identity suspension audit does not match bundle");
    }
    const sessionIds = new Set();
    for (const { record, auditEvent } of closures) {
      if (record.identityId !== identity.identityId || auditEvent?.action !== "application_session.revoked") {
        throw new Error("identity suspension session scope mismatch");
      }
      if (auditEvent.actor_id !== identityAuditEvent.actor_id ||
          auditEvent.correlation_id !== identityAuditEvent.correlation_id ||
          auditEvent.justification !== identityAuditEvent.justification ||
          record.revocationReason !== identityAuditEvent.justification) {
        throw new Error("identity suspension audit correlation mismatch");
      }
      assertApplicationSessionAudit(record, auditEvent, "application_session.revoked");
      if (sessionIds.has(record.sessionId)) throw new Error("duplicate application session closure");
      sessionIds.add(record.sessionId);
    }
    return this.#transaction((state) => {
      const previousIdentity = state.identities.get(identity.identityId);
      if (!previousIdentity || previousIdentity.status !== expectedStatus) {
        throw new Error("stale identity status");
      }
      if (identity.email !== previousIdentity.email || identity.displayName !== previousIdentity.displayName) {
        throw new Error("identity context is immutable during suspension");
      }
      const activeSessionIds = [...state.applicationSessions.values()]
        .filter((record) => record.identityId === identity.identityId && !record.revokedAt &&
          new Date(record.idleExpiresAt) > decisionTime && new Date(record.absoluteExpiresAt) > decisionTime)
        .map((record) => record.sessionId).sort();
      if (JSON.stringify(activeSessionIds) !== JSON.stringify([...sessionIds].sort())) {
        throw new Error("identity active session set changed");
      }
      for (const { record, expectedVersion } of closures) {
        const previous = state.applicationSessions.get(record.sessionId);
        if (!previous || previous.identityId !== identity.identityId || previous.version !== expectedVersion ||
            record.version !== expectedVersion + 1) throw new Error("stale application session version");
        assertApplicationSessionImmutableContext(previous, record);
        if (previous.lastSeenAt !== record.lastSeenAt || previous.idleExpiresAt !== record.idleExpiresAt ||
            previous.revokedAt || !record.revokedAt || !record.revocationReason) {
          throw new Error("invalid application session revocation");
        }
      }
      state.identities.set(identity.identityId, structuredClone(identity));
      this.#appendAudit(state, identityAuditEvent);
      for (const { record, auditEvent } of closures) {
        state.applicationSessions.set(record.sessionId, structuredClone(record));
        this.#appendAudit(state, auditEvent);
      }
      return { identity: structuredClone(identity), revokedSessions: closures.length };
    });
  }

  reactivateIdentity({ identity, expectedStatus, observedAt, identityAuditEvent }) {
    if (identity.status !== "active" || expectedStatus !== "suspended" ||
        identityAuditEvent?.action !== "identity.reactivated" ||
        identityAuditEvent.subject_id !== identity.identityId ||
        identityAuditEvent.previous_value?.status !== expectedStatus ||
        identityAuditEvent.new_value?.status !== "active" ||
        identityAuditEvent.new_value?.active_sessions !== 0 ||
        identityAuditEvent.new_value?.restored_sessions !== 0) {
      throw new Error("invalid identity reactivation bundle");
    }
    const decisionTime = new Date(observedAt);
    if (!Number.isFinite(decisionTime.valueOf())) throw new Error("invalid identity reactivation time");
    return this.#transaction((state) => {
      const previousIdentity = state.identities.get(identity.identityId);
      if (!previousIdentity || previousIdentity.status !== expectedStatus) {
        throw new Error("stale identity status");
      }
      if (identity.email !== previousIdentity.email || identity.displayName !== previousIdentity.displayName) {
        throw new Error("identity context is immutable during reactivation");
      }
      const activeSessions = [...state.applicationSessions.values()].filter((record) =>
        record.identityId === identity.identityId && !record.revokedAt &&
        new Date(record.idleExpiresAt) > decisionTime && new Date(record.absoluteExpiresAt) > decisionTime
      );
      if (activeSessions.length) throw new Error("suspended identity still has active sessions");
      state.identities.set(identity.identityId, structuredClone(identity));
      this.#appendAudit(state, identityAuditEvent);
      return structuredClone(identity);
    });
  }

  disableIdentityAndRevokeAccess({
    identity, expectedStatus, observedAt, identityAuditEvent, closures, assignmentRevocations,
  }) {
    if (identity.status !== "disabled" || !["active", "suspended"].includes(expectedStatus) ||
        identityAuditEvent?.action !== "identity.disabled" ||
        identityAuditEvent.subject_id !== identity.identityId ||
        identityAuditEvent.previous_value?.status !== expectedStatus ||
        identityAuditEvent.new_value?.status !== "disabled" ||
        !Array.isArray(closures) || !Array.isArray(assignmentRevocations) ||
        identityAuditEvent.new_value?.revoked_sessions !== closures.length ||
        identityAuditEvent.new_value?.revoked_assignments !== assignmentRevocations.length) {
      throw new Error("invalid identity disablement bundle");
    }
    const decisionTime = new Date(observedAt);
    if (!Number.isFinite(decisionTime.valueOf())) throw new Error("invalid identity disablement time");
    const orderedClosures = [...closures].sort((left, right) => left.record.sessionId.localeCompare(right.record.sessionId));
    const orderedAssignments = [...assignmentRevocations]
      .sort((left, right) => left.assignment.assignmentId.localeCompare(right.assignment.assignmentId));
    return this.#transaction((state) => {
      const previousIdentity = state.identities.get(identity.identityId);
      if (!previousIdentity || previousIdentity.status !== expectedStatus) throw new Error("stale identity status");
      if (identity.email !== previousIdentity.email || identity.displayName !== previousIdentity.displayName) {
        throw new Error("identity context is immutable during disablement");
      }
      const activeSessionIds = [...state.applicationSessions.values()]
        .filter((record) => record.identityId === identity.identityId && !record.revokedAt &&
          new Date(record.idleExpiresAt) > decisionTime && new Date(record.absoluteExpiresAt) > decisionTime)
        .map((record) => record.sessionId).sort();
      if (JSON.stringify(activeSessionIds) !== JSON.stringify(orderedClosures.map(({ record }) => record.sessionId))) {
        throw new Error("identity active session set changed");
      }
      const activeAssignmentIds = [...state.assignments.values()]
        .filter((assignment) => assignment.subjectId === identity.identityId && assignment.status === "active")
        .map((assignment) => assignment.assignmentId).sort();
      if (JSON.stringify(activeAssignmentIds) !== JSON.stringify(
        orderedAssignments.map(({ assignment }) => assignment.assignmentId),
      )) throw new Error("identity active assignment set changed");

      for (const { record, expectedVersion, auditEvent } of orderedClosures) {
        const previous = state.applicationSessions.get(record.sessionId);
        if (!previous || previous.identityId !== identity.identityId || previous.version !== expectedVersion ||
            record.version !== expectedVersion + 1 || auditEvent?.action !== "application_session.revoked") {
          throw new Error("stale application session version");
        }
        assertApplicationSessionImmutableContext(previous, record);
        if (previous.lastSeenAt !== record.lastSeenAt || previous.idleExpiresAt !== record.idleExpiresAt ||
            previous.revokedAt || !record.revokedAt || !record.revocationReason) {
          throw new Error("invalid application session revocation");
        }
        assertApplicationSessionAudit(record, auditEvent, "application_session.revoked");
        if (auditEvent.actor_id !== identityAuditEvent.actor_id ||
            auditEvent.correlation_id !== identityAuditEvent.correlation_id ||
            auditEvent.justification !== identityAuditEvent.justification ||
            record.revocationReason !== identityAuditEvent.justification) {
          throw new Error("identity disablement audit correlation mismatch");
        }
      }
      for (const { assignment, expectedVersion, auditEvent } of orderedAssignments) {
        const previous = state.assignments.get(assignment.assignmentId);
        if (!previous || previous.subjectId !== identity.identityId || previous.status !== "active" ||
            previous.version !== expectedVersion || assignment.version !== expectedVersion + 1 ||
            assignment.status !== "revoked" || auditEvent?.action !== "assignment.revoked") {
          throw new Error("stale access assignment version");
        }
        if (assignment.subjectId !== previous.subjectId || assignment.applicationId !== previous.applicationId ||
            assignment.roleId !== previous.roleId || assignment.scopeType !== previous.scopeType ||
            assignment.scopeId !== previous.scopeId || assignment.inheritedFromGroup !== previous.inheritedFromGroup ||
            JSON.stringify(assignment.permissions) !== JSON.stringify(previous.permissions) ||
            JSON.stringify(assignment.conditions) !== JSON.stringify(previous.conditions)) {
          throw new Error("assignment context is immutable during disablement");
        }
        if (auditEvent.subject_id !== identity.identityId || auditEvent.application_id !== assignment.applicationId ||
            auditEvent.actor_id !== identityAuditEvent.actor_id ||
            auditEvent.correlation_id !== identityAuditEvent.correlation_id ||
            auditEvent.justification !== identityAuditEvent.justification ||
            auditEvent.role_id !== assignment.roleId || assignment.reason !== identityAuditEvent.justification ||
            assignment.decidedBy !== identityAuditEvent.actor_id ||
            auditEvent.previous_value?.status !== "active" ||
            auditEvent.previous_value?.version !== expectedVersion ||
            auditEvent.new_value?.status !== "revoked" ||
            auditEvent.new_value?.version !== assignment.version) {
          throw new Error("identity disablement audit correlation mismatch");
        }
      }

      state.identities.set(identity.identityId, structuredClone(identity));
      this.#appendAudit(state, identityAuditEvent);
      for (const { record, auditEvent } of orderedClosures) {
        state.applicationSessions.set(record.sessionId, structuredClone(record));
        this.#appendAudit(state, auditEvent);
      }
      for (const { assignment, auditEvent } of orderedAssignments) {
        state.assignments.set(assignment.assignmentId, structuredClone(assignment));
        this.#appendAudit(state, auditEvent);
      }
      return {
        identity: structuredClone(identity),
        revokedSessions: orderedClosures.length,
        revokedAssignments: orderedAssignments.length,
      };
    });
  }

  listAllApplicationSessions() {
    return [...this.#applicationSessions.values()]
      .sort((left, right) =>
        String(right.lastSeenAt).localeCompare(String(left.lastSeenAt)) ||
        left.sessionId.localeCompare(right.sessionId)
      )
      .map((item) => structuredClone(item));
  }

  touchApplicationSession(record, expectedVersion) {
    return this.#transaction((state) => {
      const previous = state.applicationSessions.get(record.sessionId);
      if (!previous || previous.version !== expectedVersion || record.version !== expectedVersion + 1) {
        throw new Error("stale application session version");
      }
      assertApplicationSessionImmutableContext(previous, record);
      assertApplicationSessionActivityProgress(previous, record);
      if (previous.revokedAt !== record.revokedAt ||
          previous.revokedByIdentityId !== record.revokedByIdentityId ||
          previous.revocationReason !== record.revocationReason) {
        throw new Error("application session revocation cannot change during touch");
      }
      if (previous.revokedAt || new Date(previous.absoluteExpiresAt) <= new Date(record.lastSeenAt) ||
          new Date(previous.idleExpiresAt) <= new Date(record.lastSeenAt)) {
        throw new Error("inactive application session cannot be touched");
      }
      state.applicationSessions.set(record.sessionId, structuredClone(record));
      return structuredClone(record);
    });
  }

  revokeApplicationSession(record, expectedVersion, auditEvent) {
    return this.revokeApplicationSessions([{ record, expectedVersion, auditEvent }])[0];
  }

  revokeApplicationSessions(closures) {
    if (!Array.isArray(closures) || closures.length === 0) {
      throw new Error("application session closures are required");
    }
    const sessionIds = new Set();
    for (const { record, auditEvent } of closures) {
      if (!["application_session.revoked", "application_session.expired"].includes(auditEvent?.action)) {
        throw new Error("invalid application session closure audit");
      }
      assertApplicationSessionAudit(record, auditEvent, auditEvent.action);
      if (sessionIds.has(record.sessionId)) throw new Error("duplicate application session closure");
      sessionIds.add(record.sessionId);
    }
    return this.#transaction((state) => {
      for (const { record, expectedVersion } of closures) {
        const previous = state.applicationSessions.get(record.sessionId);
        if (!previous || previous.version !== expectedVersion || record.version !== expectedVersion + 1) {
          throw new Error("stale application session version");
        }
        assertApplicationSessionImmutableContext(previous, record);
        if (previous.lastSeenAt !== record.lastSeenAt || previous.idleExpiresAt !== record.idleExpiresAt) {
          throw new Error("application session activity is immutable during revocation");
        }
        if (previous.revokedAt || !record.revokedAt || !record.revocationReason) {
          throw new Error("invalid application session revocation");
        }
      }
      for (const { record, auditEvent } of closures) {
        state.applicationSessions.set(record.sessionId, structuredClone(record));
        this.#appendAudit(state, auditEvent);
      }
      return closures.map(({ record }) => structuredClone(record));
    });
  }

  listLinkRequests(status = null) {
    return [...this.#linkRequests.values()]
      .filter((item) => !status || item.status === status)
      .sort((left, right) => String(right.requestedAt).localeCompare(String(left.requestedAt)))
      .map((item) => structuredClone(item));
  }

  findActiveLinkRequest(issuer, subject, now = new Date()) {
    const match = [...this.#linkRequests.values()].find((item) =>
      item.issuer === issuer && item.subject === subject &&
      item.status === "pending" && new Date(item.expiresAt) > now,
    );
    return structuredClone(match ?? null);
  }

  findExternalIdentity(issuer, subject) {
    return structuredClone(this.#externalIdentities.get(`${issuer}\n${subject}`) ?? null);
  }

  approveLinkRequest(requestId, identityId, decidedBy, justification, auditEvent, now = new Date()) {
    if (!String(justification ?? "").trim()) throw new Error("approval justification is required");
    if (auditEvent.action !== "external_identity.link_approved") throw new Error("invalid audit action for link approval");
    if (auditEvent.actor_id !== decidedBy || auditEvent.subject_id !== identityId) throw new Error("audit identities must match approval");
    return this.#transaction((state) => {
      const request = state.linkRequests.get(requestId);
      if (!request) throw new Error("link request not found");
      if (request.status !== "pending") throw new Error("link request is not pending");
      if (now >= new Date(request.expiresAt)) throw new Error("link request has expired");
      const identity = state.identities.get(identityId);
      if (!identity) throw new Error("NSK identity not found");
      if (identity.status !== "active") throw new Error("NSK identity is not active");
      const principalKey = `${request.issuer}\n${request.subject}`;
      if (state.externalIdentities.has(principalKey)) throw new Error("external identity is already linked");
      const link = {
        externalIdentityId: randomUUID(), identityId, issuer: request.issuer,
        subject: request.subject, providerKey: request.providerKey, status: "active",
        linkedAt: now.toISOString(),
      };
      state.externalIdentities.set(principalKey, link);
      state.linkRequests.set(requestId, {
        ...request, status: "approved", targetIdentityId: identityId,
        decidedBy, decisionJustification: justification.trim(),
      });
      this.#appendAudit(state, auditEvent);
      return structuredClone(link);
    });
  }

  rejectLinkRequest(requestId, decidedBy, justification, auditEvent) {
    if (!String(justification ?? "").trim()) throw new Error("rejection justification is required");
    if (auditEvent.action !== "external_identity.link_rejected") throw new Error("invalid audit action for link rejection");
    if (auditEvent.actor_id !== decidedBy) throw new Error("audit actor must match decision maker");
    return this.#transaction((state) => {
      const request = state.linkRequests.get(requestId);
      if (!request) throw new Error("link request not found");
      if (request.status !== "pending") throw new Error("link request is not pending");
      state.linkRequests.set(requestId, {
        ...request, status: "rejected", decidedBy,
        decisionJustification: justification.trim(),
      });
      this.#appendAudit(state, auditEvent);
    });
  }

  saveAssignment(assignment, auditEvent) {
    if (auditEvent.subject_id !== assignment.subjectId || auditEvent.application_id !== assignment.applicationId) {
      throw new Error("audit context must match assignment");
    }
    return this.#transaction((state) => {
      if (!state.identities.has(assignment.subjectId) || !state.applications.has(assignment.applicationId)) {
        throw new Error("assignment prerequisites are missing");
      }
      const previous = state.assignments.get(assignment.assignmentId);
      if (previous && assignment.version !== previous.version + 1) throw new Error("stale assignment version");
      if (!previous && assignment.version !== 1) throw new Error("new assignment version must be 1");
      if (previous && !auditEvent.previous_value) throw new Error("previous value is required for update");
      state.assignments.set(assignment.assignmentId, structuredClone(assignment));
      this.#appendAudit(state, auditEvent);
    });
  }

  saveAccessRequest(request, lines, auditEvent) {
    if (request.status !== "pending" || request.version !== 1 || !lines.length ||
        auditEvent.action !== "access_request.submitted") throw new Error("invalid access request bundle");
    return this.#transaction((state) => {
      const applicationIds = [...lines.map((line) => line.applicationId)].sort();
      if (lines.some((line) => line.requestId !== request.requestId || line.status !== "pending" ||
          line.version !== 1 || !state.applications.has(line.applicationId)) ||
          new Set(applicationIds).size !== applicationIds.length) throw new Error("invalid access request lines");
      const duplicate = [...state.accessRequests.values()].find((item) => {
        if (item.status !== "pending" || item.applicantEmail !== request.applicantEmail) return false;
        const existingIds = [...state.accessRequestLines.values()].filter((line) => line.requestId === item.requestId)
          .map((line) => line.applicationId).sort();
        return JSON.stringify(existingIds) === JSON.stringify(applicationIds);
      });
      if (duplicate) return structuredClone(duplicate);
      state.accessRequests.set(request.requestId, structuredClone(request));
      lines.forEach((line) => state.accessRequestLines.set(line.lineId, structuredClone(line)));
      this.#appendAudit(state, auditEvent);
      return structuredClone(request);
    });
  }

  getAccessRequestLine(lineId) {
    return structuredClone(this.#accessRequestLines.get(lineId) ?? null);
  }

  listAccessRequests(status = null) {
    return [...this.#accessRequests.values()]
      .filter((request) => !status || request.status === status)
      .sort((left, right) => right.requestedAt.localeCompare(left.requestedAt))
      .map((request) => ({
        ...structuredClone(request),
        lines: [...this.#accessRequestLines.values()]
          .filter((line) => line.requestId === request.requestId)
          .sort((left, right) => left.applicationId.localeCompare(right.applicationId))
          .map((line) => ({ ...structuredClone(line), applicationName: stateApplicationName(this.#applications, line.applicationId) })),
      }));
  }

  approveAccessRequestLine({
    lineId, expectedVersion, targetIdentityId, assignment, assignmentAuditEvent,
    existingAssignmentId, decidedAt, decidedBy, justification, decisionAuditEvent,
  }) {
    return this.#transaction((state) => {
      const line = state.accessRequestLines.get(lineId);
      if (!line || line.status !== "pending" || line.version !== expectedVersion) throw new Error("stale access request line");
      const identity = state.identities.get(targetIdentityId);
      if (!identity || identity.status !== "active") throw new Error("target identity is unavailable");
      const assignmentId = assignment?.assignmentId ?? existingAssignmentId;
      if (assignment) {
        if (!assignmentAuditEvent || assignment.subjectId !== targetIdentityId ||
            assignment.applicationId !== line.applicationId) throw new Error("invalid assignment request bundle");
        const previous = state.assignments.get(assignment.assignmentId);
        if (previous && assignment.version !== previous.version + 1) throw new Error("stale assignment version");
        if (!previous && assignment.version !== 1) throw new Error("new assignment version must be 1");
        state.assignments.set(assignment.assignmentId, structuredClone(assignment));
        this.#appendAudit(state, assignmentAuditEvent);
      } else {
        const existing = state.assignments.get(assignmentId);
        if (!existing || existing.status !== "active" || existing.subjectId !== targetIdentityId ||
            existing.applicationId !== line.applicationId) throw new Error("active assignment is unavailable");
      }
      const updated = {
        ...line, status: "approved", targetIdentityId, assignmentId,
        decidedAt, decidedBy, decisionJustification: justification, version: line.version + 1,
      };
      state.accessRequestLines.set(lineId, updated);
      this.#refreshAccessRequestState(state, line.requestId);
      this.#appendAudit(state, decisionAuditEvent);
      return { line: structuredClone(updated), request: structuredClone(state.accessRequests.get(line.requestId)) };
    });
  }

  refuseAccessRequestLine({ lineId, expectedVersion, decidedAt, decidedBy, justification, auditEvent }) {
    return this.#transaction((state) => {
      const line = state.accessRequestLines.get(lineId);
      if (!line || line.status !== "pending" || line.version !== expectedVersion) throw new Error("stale access request line");
      const updated = {
        ...line, status: "refused", decidedAt, decidedBy,
        decisionJustification: justification, version: line.version + 1,
      };
      state.accessRequestLines.set(lineId, updated);
      this.#refreshAccessRequestState(state, line.requestId);
      this.#appendAudit(state, auditEvent);
      return { line: structuredClone(updated), request: structuredClone(state.accessRequests.get(line.requestId)) };
    });
  }

  #refreshAccessRequestState(state, requestId) {
    const request = state.accessRequests.get(requestId);
    if (!request) throw new Error("access request not found");
    const lines = [...state.accessRequestLines.values()].filter((line) => line.requestId === requestId);
    const status = accessRequestStatus(lines);
    state.accessRequests.set(requestId, { ...request, status, version: request.version + 1 });
  }

  getIdentity(identityId) {
    return structuredClone(this.#identities.get(identityId) ?? null);
  }

  findIdentityByEmail(email) {
    const normalized = String(email ?? "").trim().toLowerCase();
    const identity = [...this.#identities.values()].find((item) => item.email === normalized);
    return structuredClone(identity ?? null);
  }

  saveEmailLoginToken(record, auditEvent) {
    if (record.status !== "issued" || record.consumedAt !== null || record.invalidatedAt !== null ||
        !/^[a-f0-9]{64}$/.test(record.tokenHash)) {
      throw new Error("invalid email login record");
    }
    if (auditEvent.action !== "email_login.requested" || auditEvent.subject_id !== record.identityId) {
      throw new Error("invalid audit event for email login request");
    }
    return this.#transaction((state) => {
      const identity = state.identities.get(record.identityId);
      if (!identity || identity.status !== "active") throw new Error("email login identity is not active");
      if (state.emailLoginTokens.has(record.tokenHash)) throw new Error("email login hash must be unique");
      state.emailLoginTokens.set(record.tokenHash, structuredClone(record));
      this.#appendAudit(state, auditEvent);
    });
  }

  getEmailLoginToken(tokenHash) {
    return structuredClone(this.#emailLoginTokens.get(tokenHash) ?? null);
  }

  consumeEmailLoginToken({ tokenHash, now, auditEvent }) {
    return this.#transaction((state) => {
      const record = state.emailLoginTokens.get(tokenHash);
      if (!record || record.status !== "issued" || new Date(record.expiresAt) <= now) {
        throw new Error("invalid_or_consumed_email_login");
      }
      if (auditEvent.action !== "email_login.consumed" || auditEvent.subject_id !== record.identityId) {
        throw new Error("invalid audit event for email login consumption");
      }
      const consumed = { ...record, status: "consumed", consumedAt: new Date(now).toISOString() };
      state.emailLoginTokens.set(tokenHash, consumed);
      this.#appendAudit(state, auditEvent);
      return structuredClone(consumed);
    });
  }

  failEmailLoginToken({ tokenHash, now, auditEvent }) {
    return this.#transaction((state) => {
      const record = state.emailLoginTokens.get(tokenHash);
      if (!record || record.status !== "issued") throw new Error("invalid_email_login_delivery_failure");
      if (auditEvent.action !== "email_login.delivery_failed" || auditEvent.subject_id !== record.identityId) {
        throw new Error("invalid audit event for email login delivery failure");
      }
      const failed = { ...record, status: "delivery_failed", invalidatedAt: new Date(now).toISOString() };
      state.emailLoginTokens.set(tokenHash, failed);
      this.#appendAudit(state, auditEvent);
      return structuredClone(failed);
    });
  }

  listIdentities(status = null) {
    return [...this.#identities.values()]
      .filter((item) => !status || item.status === status)
      .sort((left, right) => left.displayName.localeCompare(right.displayName, "fr"))
      .map((item) => structuredClone(item));
  }

  getApplication(applicationId) {
    return structuredClone(this.#applications.get(applicationId) ?? null);
  }

  listApplications() {
    return [...this.#applications.values()]
      .sort((left, right) => left.displayName.localeCompare(right.displayName, "fr"))
      .map((item) => structuredClone(item));
  }

  getLatestApplicationAccessCatalog(applicationId) {
    const catalog = [...this.#applicationAccessCatalogs.values()]
      .filter((item) => item.applicationId === applicationId)
      .sort((left, right) => right.catalogVersion - left.catalogVersion)[0];
    return structuredClone(catalog ?? null);
  }

  listLatestApplicationAccessCatalogs() {
    return [...this.#applications.keys()].map((applicationId) => this.getLatestApplicationAccessCatalog(applicationId))
      .filter(Boolean).sort((left, right) => left.applicationId.localeCompare(right.applicationId));
  }

  listAssignments(identityId, applicationId) {
    return [...this.#assignments.values()]
      .filter((item) => item.subjectId === identityId && item.applicationId === applicationId)
      .map((item) => structuredClone(item));
  }

  listAllAssignments() {
    return [...this.#assignments.values()]
      .sort((left, right) =>
        left.subjectId.localeCompare(right.subjectId) ||
        left.applicationId.localeCompare(right.applicationId) ||
        left.roleId.localeCompare(right.roleId)
      )
      .map((item) => structuredClone(item));
  }

  receiveNotificationEvents(events, audits) {
    return this.#transaction((state) => {
      let created = 0;
      let alreadyPresent = 0;
      for (const event of events) {
        const key = `${event.sourceApplicationId}\n${event.eventId}`;
        const existing = state.notificationEvents.get(key);
        if (existing) {
          if (existing.eventHash !== event.eventHash) {
            throw new NotificationIngressError("notification_event_identity_conflict", 409);
          }
          alreadyPresent += 1;
          continue;
        }
        const audit = audits.get(event.eventId);
        if (!audit) throw new Error("notification audit event is required");
        state.notificationEvents.set(key, {
          ...structuredClone(event), status: "pending", processingAttempts: 0,
          availableAt: event.receivedAt, claimedAt: null, claimedBy: null,
          processedAt: null, lastErrorCode: null,
        });
        this.#appendAudit(state, audit);
        created += 1;
      }
      return { created, alreadyPresent };
    });
  }

  claimNotificationEvents({ workerId, limit, now, leaseMs }) {
    return this.#transaction((state) => {
      const staleBefore = new Date(now.valueOf() - leaseMs);
      const eligible = [...state.notificationEvents.entries()]
        .filter(([, event]) =>
          ((event.status === "pending" || event.status === "retry") && new Date(event.availableAt) <= now) ||
          (event.status === "processing" && new Date(event.claimedAt) <= staleBefore)
        )
        .sort(([, left], [, right]) =>
          String(left.availableAt).localeCompare(String(right.availableAt)) ||
          String(left.occurredAt).localeCompare(String(right.occurredAt)) ||
          left.eventId.localeCompare(right.eventId)
        )
        .slice(0, limit);
      return eligible.map(([key, event]) => {
        const claimed = {
          ...event, status: "processing", processingAttempts: event.processingAttempts + 1,
          claimedAt: now.toISOString(), claimedBy: workerId, lastErrorCode: null,
        };
        state.notificationEvents.set(key, claimed);
        return structuredClone(claimed);
      });
    });
  }

  completeNotificationEvent({ sourceApplicationId, eventId, workerId, processedAt }) {
    return this.#transaction((state) => {
      const key = `${sourceApplicationId}\n${eventId}`;
      const event = state.notificationEvents.get(key);
      if (!event || event.status !== "processing" || event.claimedBy !== workerId) {
        throw new Error("notification lease is not owned by worker");
      }
      state.notificationEvents.set(key, {
        ...event, status: "processed", claimedAt: null, claimedBy: null,
        processedAt: processedAt.toISOString(), lastErrorCode: null,
      });
    });
  }

  failNotificationEvent({
    sourceApplicationId, eventId, workerId, availableAt, errorCode, quarantined,
  }) {
    return this.#transaction((state) => {
      const key = `${sourceApplicationId}\n${eventId}`;
      const event = state.notificationEvents.get(key);
      if (!event || event.status !== "processing" || event.claimedBy !== workerId) {
        throw new Error("notification lease is not owned by worker");
      }
      state.notificationEvents.set(key, {
        ...event, status: quarantined ? "quarantined" : "retry",
        availableAt: availableAt.toISOString(), claimedAt: null, claimedBy: null,
        processedAt: null, lastErrorCode: errorCode,
      });
    });
  }

  getNotificationEvent(sourceApplicationId, eventId) {
    return structuredClone(this.#notificationEvents.get(`${sourceApplicationId}\n${eventId}`) ?? null);
  }

  listNotificationEvents() {
    return [...this.#notificationEvents.values()].map((event) => structuredClone(event));
  }

  auditCount() {
    return this.#auditEntries.length;
  }

  verifyAuditChain() {
    return verifyAuditChain(this.#auditEntries);
  }

  auditSnapshot() {
    return structuredClone(this.#auditEntries);
  }
}
