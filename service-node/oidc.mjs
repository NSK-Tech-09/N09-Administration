import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify as verifySignature,
} from "node:crypto";

export const INFOMANIAK_ISSUER = "https://login.infomaniak.com";
export const INFOMANIAK_ENDPOINTS = Object.freeze({
  authorization: `${INFOMANIAK_ISSUER}/authorize`,
  token: `${INFOMANIAK_ISSUER}/token`,
  jwks: `${INFOMANIAK_ISSUER}/oauth2/jwks`,
});
export const OIDC_TRANSACTION_COOKIE = "n09_oidc_transaction";
export const OIDC_SESSION_COOKIE = "n09_oidc_session";

function base64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function fromBase64Url(value) {
  return Buffer.from(value, "base64url");
}

function jsonFromBase64Url(value) {
  return JSON.parse(fromBase64Url(value).toString("utf8"));
}

function keyFromSecret(secret) {
  return createHash("sha256").update(secret, "utf8").digest();
}

function constantTimeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export function randomUrlSafe(size = 32) {
  return base64Url(randomBytes(size));
}

export function pkceChallenge(verifier) {
  return base64Url(createHash("sha256").update(verifier, "utf8").digest());
}

export function seal(value, secret, purpose) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", keyFromSecret(secret), iv);
  cipher.setAAD(Buffer.from(purpose, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return [base64Url(iv), base64Url(ciphertext), base64Url(cipher.getAuthTag())].join(".");
}

export function open(sealed, secret, purpose, now = Date.now()) {
  const [encodedIv, encodedCiphertext, encodedTag, extra] = String(sealed ?? "").split(".");
  if (!encodedIv || !encodedCiphertext || !encodedTag || extra) throw new Error("invalid_sealed_value");
  try {
    const decipher = createDecipheriv("aes-256-gcm", keyFromSecret(secret), fromBase64Url(encodedIv));
    decipher.setAAD(Buffer.from(purpose, "utf8"));
    decipher.setAuthTag(fromBase64Url(encodedTag));
    const plaintext = Buffer.concat([decipher.update(fromBase64Url(encodedCiphertext)), decipher.final()]);
    const value = JSON.parse(plaintext.toString("utf8"));
    if (!Number.isFinite(value.expiresAt) || value.expiresAt <= now) throw new Error("sealed_value_expired");
    return value;
  } catch (error) {
    if (error?.message === "sealed_value_expired") throw error;
    throw new Error("invalid_sealed_value");
  }
}

export function parseCookies(header) {
  const cookies = new Map();
  for (const part of String(header ?? "").split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (!name || rest.length === 0) continue;
    try { cookies.set(name, decodeURIComponent(rest.join("="))); } catch { /* ignore malformed cookie */ }
  }
  return cookies;
}

export function cookie(name, value, { maxAge, path = "/" } = {}) {
  const attributes = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`, "HttpOnly", "Secure", "SameSite=Lax"];
  if (Number.isFinite(maxAge)) attributes.push(`Max-Age=${Math.max(0, Math.floor(maxAge))}`);
  return attributes.join("; ");
}

export function oidcConfigFromEnvironment(environment = process.env) {
  const config = {
    clientId: environment.INFOMANIAK_CLIENT_ID,
    clientSecret: environment.INFOMANIAK_CLIENT_SECRET,
    redirectUri: environment.INFOMANIAK_REDIRECT_URI,
    sessionSecret: environment.N09_SESSION_SECRET,
  };
  for (const [name, value] of Object.entries(config)) {
    if (typeof value !== "string" || value.length < (name === "sessionSecret" ? 32 : 1)) {
      throw new Error(`missing_or_invalid_oidc_setting:${name}`);
    }
  }
  const redirect = new URL(config.redirectUri);
  if (redirect.protocol !== "https:") throw new Error("oidc_redirect_must_use_https");
  return config;
}

export function authorizationRequest(config, now = Date.now()) {
  const transaction = {
    state: randomUrlSafe(), nonce: randomUrlSafe(), verifier: randomUrlSafe(48),
    expiresAt: now + 10 * 60 * 1000,
  };
  const url = new URL(INFOMANIAK_ENDPOINTS.authorization);
  url.search = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: "code",
    scope: "openid profile email",
    state: transaction.state,
    nonce: transaction.nonce,
    code_challenge: pkceChallenge(transaction.verifier),
    code_challenge_method: "S256",
  }).toString();
  return { url, transaction };
}

export async function exchangeAuthorizationCode({ code, verifier, config, fetchImpl = fetch }) {
  const response = await fetchImpl(INFOMANIAK_ENDPOINTS.token, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code", code, redirect_uri: config.redirectUri,
      client_id: config.clientId, client_secret: config.clientSecret, code_verifier: verifier,
    }),
  });
  let body;
  try { body = await response.json(); } catch { body = {}; }
  if (!response.ok || typeof body.id_token !== "string") throw new Error("oidc_token_exchange_failed");
  return body.id_token;
}

export async function verifyIdToken(token, { clientId, nonce, fetchImpl = fetch, now = Date.now() }) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error("invalid_id_token");
  const header = jsonFromBase64Url(parts[0]);
  if (header.alg !== "RS256" || typeof header.kid !== "string") throw new Error("unsupported_id_token_signature");
  const jwksResponse = await fetchImpl(INFOMANIAK_ENDPOINTS.jwks, { headers: { accept: "application/json" } });
  if (!jwksResponse.ok) throw new Error("oidc_jwks_unavailable");
  const jwks = await jwksResponse.json();
  const jwk = jwks.keys?.find((candidate) => candidate.kid === header.kid && candidate.kty === "RSA");
  if (!jwk) throw new Error("oidc_signing_key_unknown");
  const validSignature = verifySignature(
    "RSA-SHA256", Buffer.from(`${parts[0]}.${parts[1]}`), createPublicKey({ key: jwk, format: "jwk" }), fromBase64Url(parts[2]),
  );
  if (!validSignature) throw new Error("invalid_id_token_signature");
  const claims = jsonFromBase64Url(parts[1]);
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  const nowSeconds = Math.floor(now / 1000);
  if (claims.iss !== INFOMANIAK_ISSUER) throw new Error("invalid_id_token_issuer");
  if (!audience.includes(clientId)) throw new Error("invalid_id_token_audience");
  if (!Number.isFinite(claims.exp) || claims.exp <= nowSeconds) throw new Error("expired_id_token");
  if (!Number.isFinite(claims.iat) || claims.iat > nowSeconds + 60) throw new Error("invalid_id_token_issued_at");
  if (typeof claims.nonce !== "string" || !constantTimeEqual(claims.nonce, nonce)) {
    throw new Error("invalid_id_token_nonce");
  }
  if (typeof claims.sub !== "string" || !claims.sub) throw new Error("missing_id_token_subject");
  return claims;
}
