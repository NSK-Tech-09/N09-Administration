function required(environment, name) {
  const value = environment[name];
  if (typeof value !== "string" || !value.trim()) throw new Error(`missing runtime setting: ${name}`);
  return value.trim();
}

function port(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65535) throw new Error("invalid runtime port");
  return parsed;
}

function positiveInteger(value, fallback, name) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`invalid runtime setting: ${name}`);
  return parsed;
}

export function mariaDbConfigFromEnvironment(environment) {
  if (environment.N09_DB_SSL !== "true") throw new Error("N09_DB_SSL must be true");
  return {
    host: required(environment, "N09_DB_HOST"),
    port: port(environment.N09_DB_PORT, 3306),
    user: required(environment, "N09_DB_USER"),
    password: required(environment, "N09_DB_PASSWORD"),
    database: required(environment, "N09_DB_NAME"),
    ssl: true,
  };
}

export function httpConfigFromEnvironment(environment) {
  const host = environment.N09_HTTP_HOST?.trim() || "127.0.0.1";
  const loopback = host === "127.0.0.1" || host === "::1";
  const trustedProxyBinding = host === "0.0.0.0" && environment.N09_TRUSTED_REVERSE_PROXY === "true";
  if (!loopback && !trustedProxyBinding) {
    throw new Error("HTTP transport requires loopback or an explicitly trusted reverse proxy");
  }
  return { host, port: port(environment.N09_HTTP_PORT ?? environment.PORT, 3000) };
}

export function applicationSessionShadowConfigFromEnvironment(environment) {
  const mode = environment.N09_SESSION_SHADOW_MODE?.trim() || "disabled";
  if (!["disabled", "observe"].includes(mode)) throw new Error("N09_SESSION_SHADOW_MODE must be disabled or observe");
  if (mode === "observe" && environment.N09_ENVIRONMENT !== "preprod") {
    throw new Error("session shadow observation is restricted to preprod");
  }
  const idleTtlMs = positiveInteger(environment.N09_SESSION_SHADOW_IDLE_TTL_MS, 30 * 60_000, "N09_SESSION_SHADOW_IDLE_TTL_MS");
  const absoluteTtlMs = positiveInteger(environment.N09_SESSION_SHADOW_ABSOLUTE_TTL_MS, 8 * 60 * 60_000, "N09_SESSION_SHADOW_ABSOLUTE_TTL_MS");
  const touchIntervalMs = positiveInteger(environment.N09_SESSION_SHADOW_TOUCH_INTERVAL_MS, 5 * 60_000, "N09_SESSION_SHADOW_TOUCH_INTERVAL_MS");
  if (idleTtlMs > absoluteTtlMs || touchIntervalMs >= idleTtlMs) {
    throw new Error("invalid session shadow lifetime settings");
  }
  return Object.freeze({ mode, applicationId: "n09-administration", idleTtlMs, absoluteTtlMs, touchIntervalMs });
}

export function tasksApplicationSessionConfigFromEnvironment(environment) {
  const mode = environment.N09_TASKS_SESSION_MODE?.trim() || "disabled";
  if (!["disabled", "issue", "enforce"].includes(mode)) {
    throw new Error("N09_TASKS_SESSION_MODE must be disabled, issue or enforce");
  }
  if (mode !== "disabled" && environment.N09_ENVIRONMENT !== "preprod") {
    throw new Error("tasks application sessions are restricted to preprod");
  }
  const idleTtlMs = positiveInteger(
    environment.N09_TASKS_SESSION_IDLE_TTL_MS,
    60 * 60_000,
    "N09_TASKS_SESSION_IDLE_TTL_MS",
  );
  const absoluteTtlMs = positiveInteger(
    environment.N09_TASKS_SESSION_ABSOLUTE_TTL_MS,
    4 * 60 * 60_000,
    "N09_TASKS_SESSION_ABSOLUTE_TTL_MS",
  );
  const touchIntervalMs = positiveInteger(
    environment.N09_TASKS_SESSION_TOUCH_INTERVAL_MS,
    5 * 60_000,
    "N09_TASKS_SESSION_TOUCH_INTERVAL_MS",
  );
  if (idleTtlMs > absoluteTtlMs || touchIntervalMs >= idleTtlMs) {
    throw new Error("invalid tasks application session lifetime settings");
  }
  return Object.freeze({
    mode,
    applicationId: "n09-suivi-taches",
    idleTtlMs,
    absoluteTtlMs,
    touchIntervalMs,
  });
}
