import { createHash, randomUUID } from "node:crypto";
import { createAuditEvent } from "./audit.mjs";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const decoder = new TextDecoder("utf-8", { fatal: true });
const CP1252_SPECIALS = new Map([
  ["€", 0x80], ["‚", 0x82], ["ƒ", 0x83], ["„", 0x84], ["…", 0x85], ["†", 0x86],
  ["‡", 0x87], ["ˆ", 0x88], ["‰", 0x89], ["Š", 0x8a], ["‹", 0x8b], ["Œ", 0x8c],
  ["Ž", 0x8e], ["‘", 0x91], ["’", 0x92], ["“", 0x93], ["”", 0x94], ["•", 0x95],
  ["–", 0x96], ["—", 0x97], ["˜", 0x98], ["™", 0x99], ["š", 0x9a], ["›", 0x9b],
  ["œ", 0x9c], ["ž", 0x9e], ["Ÿ", 0x9f],
]);
const MOJIBAKE_LEADS = new Set([0xc2, 0xc3, 0xe2, 0xef, 0xf0]);

export const HISTORICAL_TEXT_COLUMNS = Object.freeze([
  { dataset: "identities", idColumn: "identity_id", field: "display_name" },
  { dataset: "applications", idColumn: "application_id", field: "display_name" },
  { dataset: "external_identity_link_requests", idColumn: "request_id", field: "display_name_hint" },
  { dataset: "external_identity_link_requests", idColumn: "request_id", field: "decision_justification" },
  { dataset: "application_sessions", idColumn: "session_id", field: "context_label" },
  { dataset: "application_sessions", idColumn: "session_id", field: "revocation_reason" },
  { dataset: "access_assignments", idColumn: "assignment_id", field: "reason" },
  { dataset: "access_requests", idColumn: "request_id", field: "applicant_name" },
  { dataset: "access_requests", idColumn: "request_id", field: "reason" },
  { dataset: "access_request_lines", idColumn: "line_id", field: "decision_justification" },
].map(Object.freeze));

function cp1252Byte(character) {
  if (CP1252_SPECIALS.has(character)) return CP1252_SPECIALS.get(character);
  const code = character.codePointAt(0);
  return code <= 0xff ? code : null;
}

function expectedUtf8Length(firstByte) {
  if (firstByte >= 0xc2 && firstByte <= 0xdf) return 2;
  if (firstByte >= 0xe0 && firstByte <= 0xef) return 3;
  if (firstByte >= 0xf0 && firstByte <= 0xf4) return 4;
  return 0;
}

function repairPass(value) {
  const characters = [...value];
  let result = "";
  for (let index = 0; index < characters.length;) {
    const first = cp1252Byte(characters[index]);
    const length = first === null || !MOJIBAKE_LEADS.has(first) ? 0 : expectedUtf8Length(first);
    const bytes = length ? characters.slice(index, index + length).map(cp1252Byte) : [];
    const validContinuation = length > 0 && bytes.length === length && bytes.slice(1).every((byte) =>
      byte !== null && byte >= 0x80 && byte <= 0xbf
    );
    if (validContinuation) {
      try {
        result += decoder.decode(Uint8Array.from(bytes));
        index += length;
        continue;
      } catch { /* conserve le texte original lorsque la séquence n’est pas un caractère UTF-8 valide */ }
    }
    result += characters[index];
    index += 1;
  }
  return result;
}

export function repairMojibakeText(value) {
  if (typeof value !== "string") return value;
  let repaired = value;
  for (let pass = 0; pass < 3; pass += 1) {
    const next = repairPass(repaired);
    if (next === repaired) break;
    repaired = next;
  }
  return repaired;
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function summarize(repairs) {
  const fields = {};
  for (const repair of repairs) {
    const key = `${repair.dataset}.${repair.field}`;
    fields[key] = (fields[key] ?? 0) + 1;
  }
  return { count: repairs.length, fields };
}

export async function planTextEncodingRepair(repository) {
  if (typeof repository?.listHistoricalTextFields !== "function") {
    throw new Error("historical text inventory is unavailable");
  }
  const repairs = (await repository.listHistoricalTextFields()).flatMap((item) => {
    const corrected = repairMojibakeText(item.value);
    return corrected === item.value ? [] : [{ ...item, corrected }];
  });
  return { repairs, summary: summarize(repairs) };
}

export async function repairHistoricalTextEncoding(repository, {
  database, apply = false, allowRepair, confirmation, operatorEmail, justification,
  correlationId = randomUUID(),
} = {}) {
  if (typeof database !== "string" || !/_(?:preprod|prod)$/.test(database)) {
    throw new Error("text encoding repair requires an explicit preprod or prod database");
  }
  const plan = await planTextEncodingRepair(repository);
  if (!apply) return { correlationId, applied: false, ...plan.summary };
  if (allowRepair !== "true" || confirmation !== "CLEAN_NSK_TEXT_ENCODING") {
    throw new Error("text encoding repair is not explicitly confirmed");
  }
  const reason = typeof justification === "string" ? justification.trim() : "";
  if (reason.length < 30 || reason.length > 500) throw new Error("invalid text encoding repair justification");
  const email = typeof operatorEmail === "string" ? operatorEmail.trim().toLowerCase() : "";
  if (typeof repository?.findIdentityByEmail !== "function") {
    throw new Error("text encoding repair identity lookup is unavailable");
  }
  const operator = await repository.findIdentityByEmail(email);
  if (!operator || operator.status !== "active" || !UUID_PATTERN.test(operator.identityId)) {
    throw new Error("text encoding repair operator must be an active identity");
  }
  if (!plan.repairs.length) return { correlationId, applied: true, changed: 0, fields: {} };
  const manifest = plan.repairs.map((item) => ({
    dataset: item.dataset, recordId: item.recordId, field: item.field,
    before: sha256(item.value), after: sha256(item.corrected),
  }));
  const manifestHash = sha256(JSON.stringify(manifest));
  const auditEvent = createAuditEvent({
    action: "data.text_encoding_repaired", result: "success", source: "text-encoding-repair",
    correlationId, actorId: operator.identityId, justification: reason,
    previousValue: { repair_count: plan.summary.count, manifest_hash: manifestHash },
    newValue: { repair_count: plan.summary.count, fields: plan.summary.fields, manifest_hash: manifestHash },
  });
  await repository.applyHistoricalTextRepairs(plan.repairs, auditEvent);
  const remaining = await planTextEncodingRepair(repository);
  return {
    correlationId, applied: true, changed: plan.summary.count, fields: plan.summary.fields,
    remaining: remaining.summary.count,
  };
}
