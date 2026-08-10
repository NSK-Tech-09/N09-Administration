import assert from "node:assert/strict";
import test from "node:test";
import { canonicalJson, createAuditEvent, eventHash, verifyAuditChain } from "./audit.mjs";

const event = (changes = {}) => createAuditEvent({
  action: "identity.created",
  result: "success",
  source: "tests",
  correlationId: "correlation-1",
  subjectId: "identity-1",
  newValue: { status: "active" },
  justification: "Test reproductible",
  eventId: "event-1",
  occurredAt: new Date("2026-08-10T06:00:00Z"),
  ...changes,
});

test("le JSON canonique est indépendant de l’ordre des propriétés", () => {
  assert.equal(canonicalJson({ b: 2, a: { d: 4, c: 3 } }), canonicalJson({ a: { c: 3, d: 4 }, b: 2 }));
});

test("la date UTC respecte la représentation du noyau Python", () => {
  assert.match(event().occurred_at, /\+00:00$/);
  assert.equal(event().occurred_at, "2026-08-10T06:00:00+00:00");
});

test("l’empreinte est strictement identique à celle du noyau Python", () => {
  const parityEvent = event({
    correlationId: "00000000-0000-0000-0000-000000000001",
    subjectId: "00000000-0000-0000-0000-000000000002",
    eventId: "00000000-0000-0000-0000-000000000003",
  });
  assert.equal(eventHash(parityEvent), "f888aa79dd19354646c51106f99106f5131642f1a3200f545df1b14d5067c211");
});

test("un secret ne peut pas entrer dans l’audit", () => {
  assert.throws(() => event({ newValue: { access_token: "interdit" } }), /forbidden audit field/);
});

test("un événement créé ne peut plus être altéré", () => {
  const immutable = event();
  assert.throws(() => { immutable.new_value.status = "suspended"; }, TypeError);
  assert.equal(immutable.new_value.status, "active");
});

test("le chaînage détecte une altération", () => {
  const first = event();
  const firstHash = eventHash(first);
  const second = event({ eventId: "event-2", action: "identity.updated", previousValue: { status: "invited" } });
  const entries = [
    { event: first, previousHash: "", eventHash: firstHash },
    { event: second, previousHash: firstHash, eventHash: eventHash(second, firstHash) },
  ];
  assert.equal(verifyAuditChain(entries), true);
  entries[1] = { ...entries[1], eventHash: "0".repeat(64) };
  assert.equal(verifyAuditChain(entries), false);
});
