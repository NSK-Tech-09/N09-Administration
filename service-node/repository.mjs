import { randomUUID } from "node:crypto";
import { eventHash, verifyAuditChain } from "./audit.mjs";

function cloneMap(map) {
  return new Map([...map].map(([key, value]) => [key, structuredClone(value)]));
}

export class TransactionalMemoryRepository {
  #identities = new Map();
  #externalIdentities = new Map();
  #linkRequests = new Map();
  #applications = new Map();
  #assignments = new Map();
  #auditEntries = [];

  #transaction(operation) {
    const state = {
      identities: cloneMap(this.#identities),
      externalIdentities: cloneMap(this.#externalIdentities),
      linkRequests: cloneMap(this.#linkRequests),
      applications: cloneMap(this.#applications),
      assignments: cloneMap(this.#assignments),
      auditEntries: structuredClone(this.#auditEntries),
    };
    const result = operation(state);
    this.#identities = state.identities;
    this.#externalIdentities = state.externalIdentities;
    this.#linkRequests = state.linkRequests;
    this.#applications = state.applications;
    this.#assignments = state.assignments;
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
      if (!state.identities.has(identityId)) throw new Error("NSK identity not found");
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

  getApplication(applicationId) {
    return structuredClone(this.#applications.get(applicationId) ?? null);
  }

  listAssignments(identityId, applicationId) {
    return [...this.#assignments.values()]
      .filter((item) => item.subjectId === identityId && item.applicationId === applicationId)
      .map((item) => structuredClone(item));
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
