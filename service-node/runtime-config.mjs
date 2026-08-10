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
  if (host !== "127.0.0.1" && host !== "::1") {
    throw new Error("HTTP transport must remain bound to loopback before OIDC validation");
  }
  return { host, port: port(environment.N09_HTTP_PORT, 3000) };
}
