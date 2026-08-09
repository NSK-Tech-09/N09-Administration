import { cookieHeader, getCookie, INFOMANIAK_ENDPOINTS, OIDC_COOKIE, openTransaction, requiredEnvironment, verifyIdToken } from "../_lib";

function escapeHtml(value: unknown): string { return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;"); }
function resultPage(title: string, body: string, success: boolean): Response {
  return new Response(`<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)} · N09 Administration</title><style>body{margin:0;background:#f3f6f4;color:#18221e;font:16px Arial,sans-serif;display:grid;place-items:center;min-height:100vh}.card{width:min(560px,calc(100% - 40px));background:white;border:1px solid #dfe6e2;border-radius:18px;padding:32px;box-shadow:0 12px 40px #19392d14}.mark{width:52px;height:52px;border-radius:15px;display:grid;place-items:center;background:${success ? "#dff4e9" : "#fff0d8"};color:${success ? "#176341" : "#8a4f12"};font-size:24px;font-weight:bold}h1{font:600 30px Georgia,serif;margin:22px 0 12px}p{color:#5d6c65;line-height:1.6}.facts{padding:16px;border-radius:10px;background:#f3f7f5;margin:20px 0}.facts strong{color:#173e32}a{display:inline-block;padding:11px 16px;border-radius:9px;background:#173e32;color:white;text-decoration:none;font-weight:bold}</style></head><body><main class="card"><div class="mark">${success ? "✓" : "!"}</div><h1>${escapeHtml(title)}</h1>${body}<a href="/">Retour à N09 – Administration</a></main></body></html>`, { status: success ? 200 : 400, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Set-Cookie": cookieHeader(OIDC_COOKIE, "", 0) } });
}
export async function GET(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    const providerError = url.searchParams.get("error");
    if (providerError) throw new Error(`Infomaniak a interrompu la connexion (${providerError}).`);
    const code = url.searchParams.get("code"); const state = url.searchParams.get("state"); const sealed = getCookie(request, OIDC_COOKIE);
    if (!code || !state || !sealed) throw new Error("La réponse de connexion est incomplète.");
    const { clientId, clientSecret, redirectUri, sessionSecret } = requiredEnvironment();
    const transaction = await openTransaction(sealed, sessionSecret);
    if (state !== transaction.state) throw new Error("La preuve anti-falsification ne correspond pas.");
    const tokenResponse = await fetch(INFOMANIAK_ENDPOINTS.token, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: transaction.verifier,
      }),
    });
    const responseText = await tokenResponse.text();
    let tokens: { id_token?: string; error?: string; error_description?: string } = {};
    try {
      tokens = JSON.parse(responseText) as typeof tokens;
    } catch {
      if (!tokenResponse.ok) throw new Error(`Infomaniak refuse l’échange final (HTTP ${tokenResponse.status}).`);
      throw new Error("La réponse finale d’Infomaniak n’est pas exploitable.");
    }
    if (!tokenResponse.ok || !tokens.id_token) throw new Error(tokens.error_description ?? tokens.error ?? "Infomaniak n’a pas délivré de preuve d’identité.");
    const identity = await verifyIdToken(tokens.id_token, clientId, transaction.nonce);
    const displayName = identity.name || [identity.given_name, identity.family_name].filter(Boolean).join(" ") || "Utilisateur Infomaniak";
    const emailLine = identity.email ? `<p>E-mail transmis : <strong>${escapeHtml(identity.email)}</strong>${identity.email_verified ? " (vérifié)" : ""}</p>` : "<p>Aucune adresse e-mail n’a été nécessaire pour établir l’identifiant stable.</p>";
    return resultPage("Identité Infomaniak vérifiée", `<p>Le premier parcours réel fonctionne. Infomaniak a authentifié <strong>${escapeHtml(displayName)}</strong> et N09 a vérifié cryptographiquement la réponse.</p><div class="facts"><p>Identifiant externe stable : <strong>${escapeHtml(identity.sub)}</strong></p>${emailLine}<p>Aucun droit NSK n’a été créé automatiquement.</p></div>`, true);
  } catch (error) {
    const message = error instanceof Error ? error.message : "La connexion n’a pas pu être vérifiée.";
    return resultPage("Connexion non validée", `<p>${escapeHtml(message)}</p><p>Aucun compte et aucun droit n’ont été modifiés.</p>`, false);
  }
}
