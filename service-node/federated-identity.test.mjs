import assert from "node:assert/strict";
import test from "node:test";
import { createAuditEvent } from "./audit.mjs";
import { createLinkRequest, isActiveLinkRequest } from "./federated-identity.mjs";
import { TransactionalMemoryRepository } from "./repository.mjs";

const issuer = "https://login.infomaniak.com";
const identity = { identityId: "identity-1", email: "admin@example.test", displayName: "Administrateur", status: "active" };
const now = new Date("2026-08-10T09:00:00Z");

function audit(action, changes = {}) {
  return createAuditEvent({
    action, result: action.endsWith("requested") ? "pending" : "success",
    source: "tests", correlationId: crypto.randomUUID(), occurredAt: now,
    justification: "Décision contrôlée", ...changes,
  });
}

test("crée une demande temporaire sans identité NSK ni droit", () => {
  const repository = new TransactionalMemoryRepository();
  const request = createLinkRequest({
    issuer, subject: "external-42", providerKey: "infomaniak",
    emailHint: "PERSONNE@example.test", displayNameHint: "Personne", now,
  });
  repository.saveLinkRequest(request, audit("external_identity.link_requested", {
    newValue: { request_id: request.requestId, status: "pending" },
  }));

  assert.equal(repository.getLinkRequest(request.requestId).emailHint, "personne@example.test");
  assert.equal(repository.findExternalIdentity(issuer, "external-42"), null);
  assert.deepEqual(repository.listAssignments("identity-1", "tasks"), []);
  assert.equal(repository.auditCount(), 1);
  assert.equal(repository.verifyAuditChain(), true);
});

test("refuse une deuxième demande active mais autorise un retour après expiration", () => {
  const repository = new TransactionalMemoryRepository();
  const first = createLinkRequest({ issuer, subject: "returning", providerKey: "infomaniak", now, ttlMs: 60_000 });
  repository.saveLinkRequest(first, audit("external_identity.link_requested"));
  const duplicate = createLinkRequest({ issuer, subject: "returning", providerKey: "infomaniak", now: new Date(now.valueOf() + 30_000) });
  assert.throws(() => repository.saveLinkRequest(duplicate, audit("external_identity.link_requested")), /active link request/);
  assert.equal(isActiveLinkRequest(first, new Date(now.valueOf() + 30_000)), true);

  const replacement = createLinkRequest({ issuer, subject: "returning", providerKey: "infomaniak", now: new Date(now.valueOf() + 61_000) });
  repository.saveLinkRequest(replacement, audit("external_identity.link_requested"));
  assert.equal(repository.getLinkRequest(replacement.requestId).status, "pending");
});

test("l’approbation explicite crée seulement le lien externe", () => {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId }));
  const request = createLinkRequest({ issuer, subject: "external-42", providerKey: "infomaniak", now });
  repository.saveLinkRequest(request, audit("external_identity.link_requested"));
  const decisionAt = new Date(now.valueOf() + 1_000);
  const link = repository.approveLinkRequest(
    request.requestId, identity.identityId, identity.identityId, "Identité contrôlée",
    audit("external_identity.link_approved", {
      actorId: identity.identityId, subjectId: identity.identityId,
      previousValue: { status: "pending" }, newValue: { status: "approved" },
    }), decisionAt,
  );

  assert.equal(link.identityId, identity.identityId);
  assert.equal(repository.getLinkRequest(request.requestId).status, "approved");
  assert.deepEqual(repository.listAssignments(identity.identityId, "tasks"), []);
  assert.equal(repository.verifyAuditChain(), true);
});

test("le rejet ne crée aucun lien externe", () => {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId }));
  const request = createLinkRequest({ issuer, subject: "external-rejected", providerKey: "infomaniak", now });
  repository.saveLinkRequest(request, audit("external_identity.link_requested"));
  repository.rejectLinkRequest(
    request.requestId, identity.identityId, "Compte externe non reconnu",
    audit("external_identity.link_rejected", {
      actorId: identity.identityId, previousValue: { status: "pending" },
      newValue: { status: "rejected" },
    }),
  );
  assert.equal(repository.getLinkRequest(request.requestId).status, "rejected");
  assert.equal(repository.findExternalIdentity(issuer, "external-rejected"), null);
});

test("une demande expirée ne peut pas être approuvée", () => {
  const repository = new TransactionalMemoryRepository();
  repository.saveIdentity(identity, audit("identity.created", { subjectId: identity.identityId }));
  const request = createLinkRequest({ issuer, subject: "expired", providerKey: "infomaniak", now, ttlMs: 1_000 });
  repository.saveLinkRequest(request, audit("external_identity.link_requested"));
  assert.throws(() => repository.approveLinkRequest(
    request.requestId, identity.identityId, identity.identityId, "Trop tard",
    audit("external_identity.link_approved", { actorId: identity.identityId, subjectId: identity.identityId }),
    new Date(now.valueOf() + 1_001),
  ), /expired/);
  assert.equal(repository.findExternalIdentity(issuer, "expired"), null);
});
