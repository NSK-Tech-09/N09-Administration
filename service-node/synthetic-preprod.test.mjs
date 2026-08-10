import assert from "node:assert/strict";
import test from "node:test";
import { TransactionalMemoryRepository } from "./repository.mjs";
import { assertSyntheticPreprodTarget, seedSyntheticPreprod, SYNTHETIC_PREPROD } from "./synthetic-preprod.mjs";

test("verrouille l'amorçage sur une base de préproduction explicitement autorisée", () => {
  assert.throws(() => assertSyntheticPreprodTarget({ database: "n09_admin_preprod" }), /not explicitly enabled/);
  assert.throws(() => assertSyntheticPreprodTarget({ database: "n09_admin", allowSyntheticPreprod: "true" }), /preproduction/);
  assert.doesNotThrow(() => assertSyntheticPreprodTarget({
    database: "n09_admin_preprod", allowSyntheticPreprod: "true",
  }));
});

test("crée un jeu synthétique audité puis devient idempotent", async () => {
  const repository = new TransactionalMemoryRepository();
  const target = { database: "n09_admin_preprod", allowSyntheticPreprod: "true" };
  const first = await seedSyntheticPreprod(repository, { ...target, correlationId: "correlation-synthetic-1" });
  assert.deepEqual(first.created, ["identity", "application", "assignment"]);
  assert.equal(repository.auditCount(), 3);
  assert.equal(repository.verifyAuditChain(), true);
  assert.equal(repository.getIdentity(SYNTHETIC_PREPROD.identity.identityId).email.endsWith(".invalid"), true);

  const second = await seedSyntheticPreprod(repository, { ...target, correlationId: "correlation-synthetic-2" });
  assert.deepEqual(second.created, []);
  assert.equal(repository.auditCount(), 3);
});

test("refuse de réutiliser un identifiant synthétique déjà détourné", async () => {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(
    { ...SYNTHETIC_PREPROD.identity, displayName: "Collision" },
    {
      subject_id: SYNTHETIC_PREPROD.identity.identityId,
      previous_value: null,
      event_id: "event-collision",
      correlation_id: "correlation-collision",
      occurred_at: "2026-08-10T00:00:00+00:00",
      action: "test", result: "success", source: "tests",
    },
  );
  await assert.rejects(seedSyntheticPreprod(repository, {
    database: "n09_admin_preprod", allowSyntheticPreprod: "true",
  }), /identity id collision/);
});
