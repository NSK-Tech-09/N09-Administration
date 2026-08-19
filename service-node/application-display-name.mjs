const CANONICAL_APPLICATION_DISPLAY_NAMES = Object.freeze({
  "n09-administration": "N09 – Administration",
  "n09-suivi-taches": "N09 – Suivi des tâches",
});

export function applicationDisplayName(applicationId, storedDisplayName) {
  return CANONICAL_APPLICATION_DISPLAY_NAMES[applicationId]
    || storedDisplayName
    || applicationId;
}
