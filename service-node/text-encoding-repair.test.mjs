import assert from "node:assert/strict";
import test from "node:test";
import { repairHistoricalTextEncoding, repairMojibakeText } from "./text-encoding-repair.mjs";

test("répare les corruptions Windows-1252 simples, mixtes et doubles sans altérer le français correct", () => {
  assert.equal(repairMojibakeText("N09 â€“ Suivi des tÃ¢ches"), "N09 – Suivi des tâches");
  assert.equal(repairMojibakeText("préproduction gouvernÃ©e du 12 aoÃ»t 2026"), "préproduction gouvernée du 12 août 2026");
  assert.equal(repairMojibakeText("IdentitÃƒÂ© synthÃƒÂ©tique"), "Identité synthétique");
  assert.equal(repairMojibakeText("Décision déjà validée — aucun changement"), "Décision déjà validée — aucun changement");
});

test("prévisualise puis applique atomiquement toutes les réparations et devient idempotent", async () => {
  let fields = [
    { dataset: "applications", recordId: "n09-suivi-taches", field: "display_name", value: "N09 â€“ Suivi des tÃ¢ches" },
    { dataset: "access_assignments", recordId: "assignment-1", field: "reason", value: "AccÃ¨s validÃ© en aoÃ»t" },
    { dataset: "access_assignments", recordId: "assignment-2", field: "reason", value: "Accès correctement conservé" },
  ];
  let received;
  const repository = {
    listHistoricalTextFields: async () => fields,
    findIdentityByEmail: async () => ({
      identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a", status: "active",
    }),
    applyHistoricalTextRepairs: async (repairs, auditEvent) => {
      received = { repairs, auditEvent };
      fields = fields.map((item) => {
        const repair = repairs.find((candidate) => candidate.dataset === item.dataset &&
          candidate.recordId === item.recordId && candidate.field === item.field);
        return repair ? { ...item, value: repair.corrected } : item;
      });
    },
  };
  const preview = await repairHistoricalTextEncoding(repository, { database: "n09_admin_prod" });
  assert.equal(preview.applied, false);
  assert.equal(preview.count, 2);
  assert.deepEqual(preview.fields, { "applications.display_name": 1, "access_assignments.reason": 1 });

  const applied = await repairHistoricalTextEncoding(repository, {
    database: "n09_admin_prod", apply: true, allowRepair: "true",
    confirmation: "CLEAN_NSK_TEXT_ENCODING", operatorEmail: "f.travers@nsktech.fr",
    justification: "Nettoyage global et contrôlé des textes historiques mal encodés.",
  });
  assert.equal(applied.changed, 2);
  assert.equal(applied.remaining, 0);
  assert.equal(received.auditEvent.action, "data.text_encoding_repaired");
  assert.equal(received.auditEvent.actor_id, "60a40cd7-f2a4-4393-8021-9f806b42b41a");
  assert.equal(JSON.stringify(received.auditEvent).includes("AccÃ¨s"), false);

  const second = await repairHistoricalTextEncoding(repository, {
    database: "n09_admin_prod", apply: true, allowRepair: "true",
    confirmation: "CLEAN_NSK_TEXT_ENCODING", operatorEmail: "f.travers@nsktech.fr",
    justification: "Nettoyage global et contrôlé des textes historiques mal encodés.",
  });
  assert.equal(second.changed, 0);
});

test("refuse toute application non confirmée ou portée par une identité inactive", async () => {
  const repository = {
    listHistoricalTextFields: async () => [{
      dataset: "access_assignments", recordId: "assignment-1", field: "reason", value: "DÃ©cision",
    }],
    findIdentityByEmail: async () => ({ identityId: "60a40cd7-f2a4-4393-8021-9f806b42b41a", status: "suspended" }),
  };
  await assert.rejects(repairHistoricalTextEncoding(repository, {
    database: "n09_admin_prod", apply: true,
  }), /not explicitly confirmed/);
  await assert.rejects(repairHistoricalTextEncoding(repository, {
    database: "n09_admin_prod", apply: true, allowRepair: "true",
    confirmation: "CLEAN_NSK_TEXT_ENCODING", operatorEmail: "f.travers@nsktech.fr",
    justification: "Nettoyage global et contrôlé des textes historiques mal encodés.",
  }), /active identity/);
});
