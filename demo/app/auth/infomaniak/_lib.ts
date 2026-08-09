const ISSUER = "https://login.infomaniak.com";

export const INFOMANIAK_ENDPOINTS = {
  authorization: `${ISSUER}/authorize`, token: `${ISSUER}/token`, jwks: `${ISSUER}/oauth2/jwks`,
} as const;
export const OIDC_COOKIE = "n09_infomaniak_oidc";
type OidcTransaction = { state: string; nonce: string; verifier: string; expiresAt: number };
export type IdTokenClaims = { iss?: string; aud?: string | string[]; exp?: number; nonce?: string; sub?: string; name?: string; given_name?: string; family_name?: string; email?: string; email_verified?: boolean };

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
export function randomUrlSafe(size = 32): string { return base64Url(crypto.getRandomValues(new Uint8Array(size))); }
export async function sha256(value: string): Promise<string> {
  return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}
async function hmac(value: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return base64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value))));
}
export async function sealTransaction(transaction: OidcTransaction, secret: string): Promise<string> {
  const payload = base64Url(new TextEncoder().encode(JSON.stringify(transaction)));
  return `${payload}.${await hmac(payload, secret)}`;
}
export async function openTransaction(value: string, secret: string): Promise<OidcTransaction> {
  const [payload, signature, extra] = value.split(".");
  if (!payload || !signature || extra || (await hmac(payload, secret)) !== signature) throw new Error("La preuve de connexion locale est invalide.");
  const transaction = JSON.parse(new TextDecoder().decode(fromBase64Url(payload))) as OidcTransaction;
  if (transaction.expiresAt < Date.now()) throw new Error("La tentative de connexion a expiré.");
  return transaction;
}
export function getCookie(request: Request, name: string): string | null {
  for (const part of (request.headers.get("cookie") ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}
export function cookieHeader(name: string, value: string, maxAge: number): string {
  return `${name}=${encodeURIComponent(value)}; Path=/auth/infomaniak; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}
export async function verifyIdToken(token: string, clientId: string, expectedNonce: string): Promise<IdTokenClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Le jeton d’identité reçu est mal formé.");
  const header = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[0]))) as { alg?: string; kid?: string };
  if (header.alg !== "RS256" || !header.kid) throw new Error("La signature Infomaniak n’est pas reconnue.");
  const jwksResponse = await fetch(INFOMANIAK_ENDPOINTS.jwks, { cache: "no-store" });
  if (!jwksResponse.ok) throw new Error("Les clés de signature Infomaniak sont indisponibles.");
  const jwks = (await jwksResponse.json()) as { keys?: JsonWebKey[] };
  const jwk = jwks.keys?.find((candidate) => candidate.kid === header.kid);
  if (!jwk) throw new Error("La clé de signature Infomaniak est inconnue.");
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, fromBase64Url(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!valid) throw new Error("La signature Infomaniak est invalide.");
  const claims = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[1]))) as IdTokenClaims;
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== ISSUER) throw new Error("L’émetteur du jeton est invalide.");
  if (!audience.includes(clientId)) throw new Error("Le jeton ne vise pas cette application.");
  if (!claims.exp || claims.exp * 1000 <= Date.now()) throw new Error("Le jeton d’identité a expiré.");
  if (claims.nonce !== expectedNonce) throw new Error("La preuve anti-rejeu ne correspond pas.");
  if (!claims.sub) throw new Error("Infomaniak n’a fourni aucun identifiant stable.");
  return claims;
}
export function requiredEnvironment() {
  const clientId = process.env.INFOMANIAK_CLIENT_ID;
  const clientSecret = process.env.INFOMANIAK_CLIENT_SECRET;
  const redirectUri = process.env.INFOMANIAK_REDIRECT_URI;
  const sessionSecret = process.env.N09_SESSION_SECRET;
  if (!clientId || !clientSecret || !redirectUri || !sessionSecret) throw new Error("La connexion Infomaniak locale n’est pas encore configurée.");
  return { clientId, clientSecret, redirectUri, sessionSecret };
}
