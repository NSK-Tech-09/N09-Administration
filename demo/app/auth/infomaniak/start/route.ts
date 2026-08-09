import { cookieHeader, INFOMANIAK_ENDPOINTS, OIDC_COOKIE, randomUrlSafe, requiredEnvironment, sealTransaction, sha256 } from "../_lib";

export async function GET(): Promise<Response> {
  try {
    const { clientId, redirectUri, sessionSecret } = requiredEnvironment();
    const state = randomUrlSafe(); const nonce = randomUrlSafe(); const verifier = randomUrlSafe(48);
    const transaction = await sealTransaction({ state, nonce, verifier, expiresAt: Date.now() + 600_000 }, sessionSecret);
    const authorization = new URL(INFOMANIAK_ENDPOINTS.authorization);
    authorization.search = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: "code", scope: "openid profile email", state, nonce, code_challenge: await sha256(verifier), code_challenge_method: "S256" }).toString();
    return new Response(null, { status: 302, headers: { Location: authorization.toString(), "Set-Cookie": cookieHeader(OIDC_COOKIE, transaction, 600), "Cache-Control": "no-store" } });
  } catch (error) {
    return new Response(error instanceof Error ? error.message : "Connexion impossible.", { status: 500 });
  }
}
