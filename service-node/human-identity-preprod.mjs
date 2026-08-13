import { randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function normalizedText(value) {
  return typeof value === "string" ? value.trim() : "";
}

export function assertHumanIdentityPreprodTarget({
  database, allowCreation, operatorIdentityId, email, displayName, justification,
}) {
  if (allowCreation !== "true") throw new Error("human identity creation is not explicitly enabled");
  if (typeof database !== "string" || !database.endsWith("_preprod")) {
    throw new Error("human identity creation can only target preproduction");
  }
  if (!UUID_PATTERN.test(normalizedText(operatorIdentityId))) {
    throw new Error("a valid operator identity id is required");
  }
  const normalizedEmail = normalizedText(email).toLowerCase();
  if (!EMAIL_PATTERN.test(normalizedEmail) || normalizedEmail.endsWith(".invalid")) {
    throw new Error("a valid human email address is required");
  }
  const normalizedDisplayName = normalizedText(displayName);
  if (normalizedDisplayName.length < 2 || normalizedDisplayName.length > 120) {
    throw new Error("a display name between 2 and 120 characters is required");
  }
  const normalizedJustification = normalizedText(justification);
  if (normalizedJustification.length < 20 || normalizedJustification.length > 500) {
    throw new Error("an explicit justification between 20 and 500 characters is required");
  }
}

export async function createHumanIdentityPreprod(repository, {
  database,
  allowCreation,
  operatorIdentityId,
  email,
  displayName,
  justification,
  identityId = randomUUID(),
  correlationId = randomUUID(),
} = {}) {
  assertHumanIdentityPreprodTarget({
    database, allowCreation, operatorIdentityId, email, displayName, justification,
  });
  if (!UUID_PATTERN.test(normalizedText(identityId))) throw new Error("a valid target identity id is required");

  const operator = await repository.getIdentity(operatorIdentityId);
  if (!operator || operator.status !== "active") throw new Error("operator identity must exist and be active");

  const normalizedEmail = normalizedText(email).toLowerCase();
  const normalizedDisplayName = normalizedText(displayName);
  const identities = await repository.listIdentities();
  const existingByEmail = identities.find((item) => item.email.toLowerCase() === normalizedEmail);
  if (existingByEmail) {
    if (existingByEmail.displayName !== normalizedDisplayName || existingByEmail.status !== "active") {
      throw new Error("human identity email already exists with a different controlled definition");
    }
    return { correlationId, identityId: existingByEmail.identityId, created: false };
  }
  if (await repository.getIdentity(identityId)) throw new Error("target identity id already exists");

  await repository.saveIdentity({
    identityId,
    email: normalizedEmail,
    displayName: normalizedDisplayName,
    status: "active",
  }, createAuditEvent({
    action: "identity.human_preprod_created",
    result: "success",
    source: "human-identity-preprod",
    correlationId,
    actorId: operatorIdentityId,
    subjectId: identityId,
    justification: normalizedText(justification),
    newValue: { status: "active", access_assignments: 0 },
  }));

  return { correlationId, identityId, created: true };
}
