import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { createHttpHandler } from "./http.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

async function withServer(options, operation) {
  const server = createServer(createHttpHandler(options));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    await operation(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

test("recoit les evenements authentifies dans une boite centrale idempotente", async () => {
  const repository = new TransactionalMemoryRepository();
  const applicationId = "n09-suivi-taches";
  repository.saveApplication({
    applicationId, displayName: "N09 – Suivi des tâches", status: "active", registrationPolicy: "closed",
  }, createAuditEvent({
    action: "application.registered", result: "success", source: "notification-http-tests",
    correlationId: randomUUID(), applicationId,
  }));
  const payload = {
    contract_version: 1,
    events: [{
      event_id: "event_0123456789abcdefabcd", event_type: "task.restored",
      task_id: "task_1", site_id: "site_1", actor_id: "user_1",
      aggregate_id: "task_1", payload: { task_version: 7 },
      occurred_at: new Date(Date.now() - 1_000).toISOString(),
    }],
  };
  await withServer({
    repository,
    authenticate: async () => ({ applicationId, audience: applicationId }),
  }, async (baseUrl) => {
    const send = () => fetch(`${baseUrl}/internal/v1/notification-events`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
    });
    const first = await send();
    assert.equal(first.status, 202);
    assert.deepEqual(await first.json(), { contract_version: 1, accepted: 1, already_present: 0 });
    const replay = await send();
    assert.equal(replay.status, 200);
    assert.deepEqual(await replay.json(), { contract_version: 1, accepted: 0, already_present: 1 });
  });
  assert.equal(repository.getNotificationEvent(applicationId, payload.events[0].event_id).status, "pending");
});

test("ferme la route sans authentification et borne methode et format", async () => {
  const repository = { getApplication: async () => null };
  await withServer({ repository }, async (baseUrl) => {
    const wrongMethod = await fetch(`${baseUrl}/internal/v1/notification-events`);
    assert.equal(wrongMethod.status, 405);
    assert.equal(wrongMethod.headers.get("allow"), "POST");
    const wrongFormat = await fetch(`${baseUrl}/internal/v1/notification-events`, { method: "POST", body: "{}" });
    assert.equal(wrongFormat.status, 415);
    const anonymous = await fetch(`${baseUrl}/internal/v1/notification-events`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ contract_version: 1, events: [] }),
    });
    assert.equal(anonymous.status, 401);
    assert.deepEqual(await anonymous.json(), { error: "authentication_required" });
  });
});
