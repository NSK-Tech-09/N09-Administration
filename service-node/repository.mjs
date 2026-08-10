import { eventHash, verifyAuditChain } from "./audit.mjs";

function cloneMap(map) {
  return new Map([...map].map(([key, value]) => [key, structuredClone(value)]));
}

export class TransactionalMemoryRepository {
  #identities = new Map();
  #applications = new Map();
  #assignments = new Map();
  #auditEntries = [];

  #transaction(operation) {
    const state = {
      identities: cloneMap(this.#identities),
      applications: cloneMap(this.#applications),
      assignments: cloneMap(this.#assignments),
      auditEntries: structuredClone(this.#auditEntries),
    };
    const result = operation(state);
    this.#identities = state.identities;
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
