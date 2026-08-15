import { createHash, randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";
import {
  authorizeAccessDecisionAdministration,
  prepareAccessAssignment,
} from "./access-decision-admin.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const APPLICATION_ID = /^[a-z][a-z0-9:-]{1,99}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export class AccessRequestError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

function cleanText(value, minimum, maximum, code) {
  const normalized = typeof value === "string" ? value.trim().replace(/\s+/g, " ") : "";
  if (normalized.length < minimum || normalized.length > maximum || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new AccessRequestError(code);
  }
  return normalized;
}

function cleanEmail(value) {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (normalized.length > 320 || !EMAIL.test(normalized)) throw new AccessRequestError("invalid_email");
  return normalized;
}

function cleanApplicationIds(value) {
  if (!Array.isArray(value)) throw new AccessRequestError("applications_required");
  const normalized = [...new Set(value.map((item) => typeof item === "string" ? item.trim() : ""))].sort();
  if (normalized.length < 1 || normalized.length > 10 || normalized.some((item) => !APPLICATION_ID.test(item))) {
    throw new AccessRequestError("invalid_applications");
  }
  return normalized;
}

export async function submitPublicAccessRequest(repository, {
  displayName,
  email,
  applicationIds,
  reason,
  correlationId = randomUUID(),
  now = new Date(),
} = {}) {
  const applicantName = cleanText(displayName, 2, 120, "invalid_display_name");
  const applicantEmail = cleanEmail(email);
  const requestedApplicationIds = cleanApplicationIds(applicationIds);
  const requestReason = cleanText(reason, 20, 1000, "invalid_reason");

  const applications = await Promise.all(requestedApplicationIds.map((applicationId) =>
    repository.getApplication(applicationId)
  ));
  const unavailable = applications.some((application) =>
    !application || application.status !== "active" || application.registrationPolicy !== "approval"
  );
  if (unavailable) throw new AccessRequestError("application_not_requestable", 409);

  const requestId = randomUUID();
  const request = {
    requestId,
    applicantName,
    applicantEmail,
    reason: requestReason,
    status: "pending",
    requestedAt: now.toISOString(),
    version: 1,
  };
  const lines = requestedApplicationIds.map((applicationId) => ({
    lineId: randomUUID(), requestId, applicationId, status: "pending",
    targetIdentityId: null, assignmentId: null, decidedAt: null,
    decidedBy: null, decisionJustification: "", version: 1,
  }));
  const auditEvent = createAuditEvent({
    action: "access_request.submitted",
    result: "success",
    source: "public-portal",
    correlationId,
    newValue: {
      request_id: requestId,
      status: "pending",
      application_ids: requestedApplicationIds,
      applicant_email_hash: createHash("sha256").update(applicantEmail, "utf8").digest("hex"),
    },
    justification: requestReason,
    occurredAt: now,
  });
  const saved = await repository.saveAccessRequest(request, lines, auditEvent);
  return { requestId: saved.requestId, correlationId, status: saved.status };
}

export async function approveAccessRequestLine(repository, {
  lineId,
  identityId,
  roleId,
  scopeType,
  scopeId = null,
  catalogVersion,
  operatorIdentityId,
  justification,
  correlationId = randomUUID(),
  now = new Date(),
} = {}) {
  if (!UUID.test(String(lineId ?? ""))) throw new AccessRequestError("invalid_request_line");
  const line = await repository.getAccessRequestLine(lineId);
  if (!line || line.status !== "pending") throw new AccessRequestError("request_line_not_pending", 409);

  const prepared = await prepareAccessAssignment(repository, {
    identityId,
    applicationId: line.applicationId,
    roleId,
    scopeType,
    scopeId,
    catalogVersion,
    operatorIdentityId,
    justification,
    correlationId,
    now,
  });
  const decisionAudit = createAuditEvent({
    action: "access_request.approved",
    result: "success",
    source: "access-request-administration",
    correlationId,
    actorId: operatorIdentityId,
    subjectId: identityId,
    applicationId: line.applicationId,
    roleId,
    scopeType: prepared.assignment.scopeType,
    scopeId: prepared.assignment.scopeId,
    previousValue: { status: "pending", version: line.version },
    newValue: {
      status: "approved", version: line.version + 1,
      assignment_id: prepared.assignment.assignmentId,
    },
    justification,
    occurredAt: now,
  });
  const result = await repository.approveAccessRequestLine({
    lineId,
    expectedVersion: line.version,
    targetIdentityId: identityId,
    assignment: prepared.created ? prepared.assignment : null,
    assignmentAuditEvent: prepared.created ? prepared.auditEvent : null,
    existingAssignmentId: prepared.assignment.assignmentId,
    decidedAt: now.toISOString(),
    decidedBy: operatorIdentityId,
    justification: justification.trim(),
    decisionAuditEvent: decisionAudit,
  });
  return { ...result, correlationId };
}

export async function refuseAccessRequestLine(repository, {
  lineId,
  operatorIdentityId,
  justification,
  correlationId = randomUUID(),
  now = new Date(),
} = {}) {
  if (!UUID.test(String(lineId ?? ""))) throw new AccessRequestError("invalid_request_line");
  if (!UUID.test(String(operatorIdentityId ?? ""))) throw new AccessRequestError("invalid_operator");
  const reason = cleanText(justification, 20, 500, "invalid_justification");
  const access = await authorizeAccessDecisionAdministration(repository, operatorIdentityId, now);
  if (!access.allowed) throw new AccessRequestError("access_denied", 403);
  const line = await repository.getAccessRequestLine(lineId);
  if (!line || line.status !== "pending") throw new AccessRequestError("request_line_not_pending", 409);
  const auditEvent = createAuditEvent({
    action: "access_request.refused",
    result: "success",
    source: "access-request-administration",
    correlationId,
    actorId: operatorIdentityId,
    applicationId: line.applicationId,
    previousValue: { status: "pending", version: line.version },
    newValue: { status: "refused", version: line.version + 1 },
    justification: reason,
    occurredAt: now,
  });
  const result = await repository.refuseAccessRequestLine({
    lineId,
    expectedVersion: line.version,
    decidedAt: now.toISOString(),
    decidedBy: operatorIdentityId,
    justification: reason,
    auditEvent,
  });
  return { ...result, correlationId };
}
