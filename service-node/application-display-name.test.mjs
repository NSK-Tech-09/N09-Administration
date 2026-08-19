import assert from "node:assert/strict";
import test from "node:test";
import { applicationDisplayName } from "./application-display-name.mjs";

test("présente le libellé canonique des applications centrales malgré une valeur historique corrompue", () => {
  assert.equal(
    applicationDisplayName("n09-suivi-taches", "N09 â€“ Suivi des tÃ¢ches"),
    "N09 – Suivi des tâches",
  );
  assert.equal(
    applicationDisplayName("n09-administration", "N09 â€“ Administration"),
    "N09 – Administration",
  );
});

test("conserve le libellé publié des autres applications", () => {
  assert.equal(applicationDisplayName("n09-energie", "N09 – Énergie"), "N09 – Énergie");
  assert.equal(applicationDisplayName("application-inconnue"), "application-inconnue");
});
