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
  #notificationEvents = new Map();
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
      notificationEvents: cloneMap(this.#notificationEvents),
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
    this.#notificationEvents = state.notificationEvents;
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

  getIdentity(identityId) {
    return structuredClone(this.#identities.get(identityId) ?? null);
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
