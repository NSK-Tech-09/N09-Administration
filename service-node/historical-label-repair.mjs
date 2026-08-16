import { randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const HISTORICAL_LABEL_REPAIRS = Object.freeze([
  Object.freeze({
    kind: "identity",
    id: "ac31d4fa-ca3f-4d34-87b3-3d8e436b30de",
    legacy: "Fred TRAVERS \u00e2\u20ac\u201d Recette",
    canonical: "Fred TRAVERS — Recette",
  }),
  Object.freeze({
    kind: "identity",
    id: "00000000-0000-4000-8000-000000000009",
    legacy: "Identit\u00c3\u00a9 synth\u00c3\u00a9tique NSK Tech 09",
    canonical: "Identité synthétique NSK Tech 09",
  }),
  Object.freeze({
    kind: "application",
    id: "n09-synthetic",
    legacy: "Application synth\u00c3\u00a9tique NSK Tech 09",
    canonical: "Application synthétique NSK Tech 09",
  }),
  Object.freeze({
    kind: "application",
    id: "n09-administration",
    legacy: "N09 \u00e2\u20ac\u201c Administration",
    canonical: "N09 – Administration",
  }),
]);

function normalizedText(value) {
  return typeof value === "string" ? value.trim() : "";
}

export function assertHistoricalLabelRepairTarget({
  database, apply, allowRepair, operatorIdentityId, justification,
}) {
  if (typeof database !== "string" || !/_(?:preprod|prod)$/.test(database)) {
    throw new Error("historical label repair requires an explicit preprod or prod database");
  }
  if (!apply) return;
  if (allowRepair !== "true") throw new Error("historical label repair is not explicitly enabled");
  if (!UUID_PATTERN.test(normalizedText(operatorIdentityId))) {
    throw new Error("a valid operator identity id is required");
  }
  const reason = normalizedText(justification);
  if (reason.length < 20 || reason.length > 500) {
    throw new Error("an explicit repair justification between 20 and 500 characters is required");
  }
}

async function readTarget(repository, repair) {
  return repair.kind === "identity"
    ? repository.getIdentity(repair.id)
    : repository.getApplication(repair.id);
}

export async function repairHistoricalLabels(repository, {
  database,
  apply = false,
  allowRepair,
  operatorIdentityId,
  justification,
  correlationId = randomUUID(),
} = {}) {
  assertHistoricalLabelRepairTarget({ database, apply, allowRepair, operatorIdentityId, justification });

  const inspected = [];
  for (const repair of HISTORICAL_LABEL_REPAIRS) {
    const current = await readTarget(repository, repair);
    if (!current) {
      inspected.push({ ...repair, state: "missing", current: null });
      continue;
    }
    if (current.displayName === repair.canonical) {
      inspected.push({ ...repair, state: "canonical", current });
      continue;
    }
    if (current.displayName !== repair.legacy) {
      throw new Error(`unexpected historical label for ${repair.kind}:${repair.id}`);
    }
    inspected.push({ ...repair, state: "repairable", current });
  }

  const planned = inspected.filter((item) => item.state === "repairable");
  if (!apply) {
    return {
      correlationId,
      applied: false,
      planned: planned.map(({ kind, id, legacy, canonical }) => ({ kind, id, legacy, canonical })),
      unchanged: inspected.filter((item) => item.state === "canonical").map((item) => `${item.kind}:${item.id}`),
      missing: inspected.filter((item) => item.state === "missing").map((item) => `${item.kind}:${item.id}`),
    };
  }

  const operator = await repository.getIdentity(operatorIdentityId);
  if (!operator || operator.status !== "active") throw new Error("operator identity must exist and be active");

  const changed = [];
  for (const item of planned) {
    const auditEvent = createAuditEvent({
      action: `${item.kind}.display_name_repaired`,
      result: "success",
      source: "historical-label-repair",
      correlationId,
      actorId: operatorIdentityId,
      subjectId: item.kind === "identity" ? item.id : null,
      applicationId: item.kind === "application" ? item.id : null,
      previousValue: { display_name: item.legacy },
      newValue: { display_name: item.canonical },
      justification: normalizedText(justification),
    });
    const corrected = { ...item.current, displayName: item.canonical };
    if (item.kind === "identity") await repository.saveIdentity(corrected, auditEvent);
    else await repository.saveApplication(corrected, auditEvent);
    changed.push(`${item.kind}:${item.id}`);
  }

  return {
    correlationId,
    applied: true,
    changed,
    unchanged: inspected.filter((item) => item.state === "canonical").map((item) => `${item.kind}:${item.id}`),
    missing: inspected.filter((item) => item.state === "missing").map((item) => `${item.kind}:${item.id}`),
  };
}
