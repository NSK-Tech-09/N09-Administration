import assert from "node:assert/strict";
import test from "node:test";
import { decideAccess } from "./access.mjs";

const now = new Date("2026-08-09T12:00:00Z");
const identity = { identityId: "identity-1", status: "active" };
const application = { applicationId: "tasks", status: "active" };
const assignment = (changes = {}) => ({
  assignmentId: "assignment-1",
  subjectId: identity.identityId,
  applicationId: "tasks",
  roleId: "reader",
  permissions: ["tasks:read"],
  scopeType: "site",
  scopeId: "site-09",
  conditions: [],
  status: "active",
  validFrom: null,
  validUntil: null,
  ...changes,
});
const decide = (changes = {}) => decideAccess({
  identity,
  application,
  assignments: [assignment()],
  requiredPermission: "tasks:read",
  scopeType: "site",
  scopeId: "site-09",
  now,
  ...changes,
});

const vectors = [
  ["accord explicite contextualisé", {}, "access_granted", true],
  ["affectation globale couvrant un site", { assignments: [assignment({
    roleId: "tasks-administrator", permissions: ["tasks:read", "tasks:write", "tasks:admin"],
    scopeType: null, scopeId: null,
  })], requiredPermission: "tasks:write" }, "access_granted", true],
  ["affectation absente", { assignments: [] }, "assignment_missing", false],
  ["identité suspendue", { identity: { ...identity, status: "suspended" } }, "identity_not_active", false],
  ["identité désactivée", { identity: { ...identity, status: "disabled" } }, "identity_not_active", false],
  ["affectation expirée", { assignments: [assignment({ validUntil: "2026-08-09T11:59:59Z" })] }, "permission_or_validity_missing", false],
  ["permission inconnue", { requiredPermission: "tasks:admin" }, "permission_or_validity_missing", false],
  ["autre périmètre", { scopeId: "site-11" }, "scope_mismatch", false],
  ["condition MFA absente", { assignments: [assignment({ conditions: ["mfa"] })] }, "conditions_not_satisfied", false],
  ["affectation de groupe", { assignments: [assignment({ inheritedFromGroup: "group-1" })] }, "access_granted", true],
  ["autre application", { assignments: [assignment({ applicationId: "energy" })] }, "assignment_missing", false],
  ["super-administrateur sans droit métier", { assignments: [assignment({ roleId: "nsk_super_admin", permissions: ["administration:manage"], scopeType: null, scopeId: null })] }, "permission_or_validity_missing", false],
  ["application en maintenance", { application: { ...application, status: "maintenance" } }, "application_not_active", false],
];

for (const [name, changes, reasonCode, allowed] of vectors) {
  test(`conformité Python : ${name}`, () => {
    assert.deepEqual(decide(changes), allowed
      ? { allowed, reasonCode, assignment: changes.assignments?.[0] || assignment() }
      : { allowed, reasonCode });
  });
}
