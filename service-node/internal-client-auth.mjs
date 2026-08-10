import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export const INTERNAL_CLIENT_HEADERS = Object.freeze({
  clientId: "x-n09-client-id",
  timestamp: "x-n09-timestamp",
  nonce: "x-n09-nonce",
  signature: "x-n09-signature",
});

export function canonicalInternalRequest({ method, pathname, timestamp, nonce, rawBody }) {
  const bodyHash = createHash("sha256").update(rawBody, "utf8").digest("hex");
  return `${method.toUpperCase()}\n${pathname}\n${timestamp}\n${nonce}\n${bodyHash}`;
}

export function signInternalRequest(secret, request) {
  return createHmac("sha256", secret).update(canonicalInternalRequest(request), "utf8").digest("hex");
}

export function internalClientsFromEnvironment(environment = process.env) {
  const clientId = environment.N09_TASKS_INTERNAL_CLIENT_ID?.trim();
  const secret = environment.N09_TASKS_INTERNAL_CLIENT_SECRET?.trim();
  const applicationId = environment.N09_TASKS_APPLICATION_ID?.trim() || "n09-suivi-taches";
  if (!clientId && !secret) return new Map();
  if (!clientId || !secret || secret.length < 32) throw new Error("invalid tasks internal client configuration");
  return new Map([[clientId, Object.freeze({ applicationId, secret })]]);
}

export function createInternalClientAuthenticator({
  clients, now = () => Date.now(), maxSkewMs = 30_000,
} = {}) {
  if (!(clients instanceof Map)) throw new Error("internal clients map is required");
  const seenNonces = new Map();
  return async function authenticate(request, { rawBody = "" } = {}) {
    const clientId = request.headers[INTERNAL_CLIENT_HEADERS.clientId];
    const timestamp = request.headers[INTERNAL_CLIENT_HEADERS.timestamp];
    const nonce = request.headers[INTERNAL_CLIENT_HEADERS.nonce];
    const suppliedSignature = request.headers[INTERNAL_CLIENT_HEADERS.signature];
    if (![clientId, timestamp, nonce, suppliedSignature].every((value) => typeof value === "string" && value)) return null;
    const client = clients.get(clientId);
    if (!client || !/^[0-9a-f-]{36}$/i.test(nonce) || !/^\d{13}$/.test(timestamp) || !/^[0-9a-f]{64}$/i.test(suppliedSignature)) return null;
    const requestTime = Number(timestamp);
    const currentTime = now();
    if (!Number.isSafeInteger(requestTime) || Math.abs(currentTime - requestTime) > maxSkewMs) return null;

    for (const [key, expiresAt] of seenNonces) if (expiresAt <= currentTime) seenNonces.delete(key);
    const nonceKey = `${clientId}\n${nonce}`;
    if (seenNonces.has(nonceKey)) return null;
    const expectedSignature = signInternalRequest(client.secret, {
      method: request.method, pathname: new URL(request.url, "https://n09.invalid").pathname,
      timestamp, nonce, rawBody,
    });
    const expected = Buffer.from(expectedSignature, "hex");
    const supplied = Buffer.from(suppliedSignature, "hex");
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) return null;
    seenNonces.set(nonceKey, currentTime + maxSkewMs);
    return { applicationId: client.applicationId, audience: client.applicationId };
  };
}
