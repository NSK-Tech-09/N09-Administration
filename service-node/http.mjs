import { randomUUID, timingSafeEqual } from "node:crypto";
import { evaluateAccessRequestAsync } from "./api.mjs";
import {
  authorizationRequest, cookie, exchangeAuthorizationCode, INFOMANIAK_ISSUER,
  OIDC_SESSION_COOKIE, OIDC_TRANSACTION_COOKIE, open, parseCookies, seal, verifyIdToken,
} from "./oidc.mjs";

const DEFAULT_MAX_BODY_BYTES = 64 * 1024;

class HttpInputError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function writeJson(response, status, body, correlationId = null) {
  const payload = JSON.stringify(body);
  response.statusCode = status;
  response.setHeader("cache-control", "no-store");
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("x-content-type-options", "nosniff");
  if (correlationId) response.setHeader("x-correlation-id", correlationId);
  response.end(payload);
}

function escapeHtml(value) {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}

function writeHtml(response, status, title, content, setCookies = []) {
  response.statusCode = status;
  response.setHeader("cache-control", "no-store");
  response.setHeader("content-type", "text/html; charset=utf-8");
  response.setHeader("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("x-content-type-options", "nosniff");
  if (setCookies.length) response.setHeader("set-cookie", setCookies);
  response.end(`<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)} · N09 Administration</title><style>*{box-sizing:border-box}body{margin:0;background:#f3f6f4;color:#18221e;font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:100vh}.card{width:min(640px,calc(100% - 36px));background:#fff;border:1px solid #dfe6e2;border-radius:18px;padding:34px;box-shadow:0 12px 40px #19392d14}.brand{color:#21825e;font-size:12px;font-weight:800;letter-spacing:1px}h1{font:600 31px Georgia,serif;margin:22px 0 12px}p{color:#5d6c65;line-height:1.6}.facts{padding:16px;border-radius:10px;background:#f3f7f5;margin:20px 0}.facts strong{color:#173e32}.button,button{display:inline-block;border:0;padding:12px 17px;border-radius:9px;background:#173e32;color:#fff;text-decoration:none;font-weight:bold;cursor:pointer}.note{font-size:13px}</style></head><body><main class="card"><div class="brand">N09 · ADMINISTRATION · NSK TECH 09</div>${content}</main></body></html>`);
}

async function readJson(request, maxBodyBytes) {
  const contentType = request.headers["content-type"] ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new HttpInputError(415, "unsupported_media_type");
  }

  const chunks = [];
  let received = 0;
  for await (const chunk of request) {
    received += chunk.length;
    if (received > maxBodyBytes) throw new HttpInputError(413, "request_too_large");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpInputError(400, "invalid_json");
  }
}

export function createHttpHandler({ repository, authenticate = async () => null, oidcConfig = null, fetchImpl = fetch, maxBodyBytes = DEFAULT_MAX_BODY_BYTES }) {
  if (!repository) throw new Error("repository is required");
  if (typeof authenticate !== "function") throw new Error("authenticate must be a function");

  return async function handle(request, response) {
    const url = new URL(request.url, "https://n09.invalid");
    if (url.pathname === "/health" && request.method === "GET") {
      writeJson(response, 200, { status: "ok" });
      return;
    }
    if (url.pathname === "/" && request.method === "GET") {
      let session = null;
      if (oidcConfig) {
        try { session = open(parseCookies(request.headers.cookie).get(OIDC_SESSION_COOKIE), oidcConfig.sessionSecret, "oidc-session"); } catch { /* anonymous */ }
      }
      const content = session
        ? `<h1>Identité Infomaniak vérifiée</h1><p>Bienvenue <strong>${escapeHtml(session.displayName)}</strong>. La preuve cryptographique est valide.</p><div class="facts"><p>État NSK : <strong>rattachement requis</strong></p><p>Aucun compte, rôle ou droit n’a été créé automatiquement.</p></div><form method="post" action="/auth/logout"><button type="submit">Fermer la session</button></form>`
        : `<h1>Le cœur d’identité est prêt</h1><p>Connecte-toi avec Infomaniak pour présenter une preuve d’identité au registre central NSK.</p><div class="facts"><p><strong>Connexion réelle :</strong> Authorization Code + PKCE S256.</p><p><strong>Zéro privilège implicite :</strong> une identité inconnue reste sans droit.</p></div>${oidcConfig ? '<a class="button" href="/auth/infomaniak/start">Continuer avec Infomaniak</a>' : '<p>Le fournisseur OIDC n’est pas encore configuré.</p>'}`;
      writeHtml(response, 200, "Accueil", content);
      return;
    }
    if (url.pathname === "/auth/infomaniak/start" && request.method === "GET") {
      if (!oidcConfig) { writeJson(response, 503, { error: "oidc_not_configured" }); return; }
      const { url: authorizationUrl, transaction } = authorizationRequest(oidcConfig);
      response.statusCode = 302;
      response.setHeader("cache-control", "no-store");
      response.setHeader("location", authorizationUrl.toString());
      response.setHeader("set-cookie", cookie(OIDC_TRANSACTION_COOKIE, seal(transaction, oidcConfig.sessionSecret, "oidc-transaction"), { maxAge: 600, path: "/auth/infomaniak" }));
      response.end();
      return;
    }
    if (url.pathname === "/auth/infomaniak/callback" && request.method === "GET") {
      const clearTransaction = cookie(OIDC_TRANSACTION_COOKIE, "", { maxAge: 0, path: "/auth/infomaniak" });
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        if (url.searchParams.has("error")) throw new Error("oidc_provider_rejected");
        const code = url.searchParams.get("code");
        const returnedState = url.searchParams.get("state");
        if (!code || !returnedState) throw new Error("incomplete_oidc_callback");
        const sealedTransaction = parseCookies(request.headers.cookie).get(OIDC_TRANSACTION_COOKIE);
        const transaction = open(sealedTransaction, oidcConfig.sessionSecret, "oidc-transaction");
        if (returnedState.length !== transaction.state.length || !timingSafeEqual(Buffer.from(returnedState), Buffer.from(transaction.state))) {
          throw new Error("oidc_state_mismatch");
        }
        const idToken = await exchangeAuthorizationCode({ code, verifier: transaction.verifier, config: oidcConfig, fetchImpl });
        const claims = await verifyIdToken(idToken, { clientId: oidcConfig.clientId, nonce: transaction.nonce, fetchImpl });
        const displayName = claims.name || [claims.given_name, claims.family_name].filter(Boolean).join(" ") || "Utilisateur Infomaniak";
        const session = { issuer: INFOMANIAK_ISSUER, subject: claims.sub, displayName, status: "link_required", expiresAt: Date.now() + 8 * 60 * 60 * 1000 };
        const sessionCookie = cookie(OIDC_SESSION_COOKIE, seal(session, oidcConfig.sessionSecret, "oidc-session"), { maxAge: 8 * 60 * 60 });
        response.statusCode = 303;
        response.setHeader("cache-control", "no-store");
        response.setHeader("location", "/");
        response.setHeader("set-cookie", [clearTransaction, sessionCookie]);
        response.end();
      } catch (error) {
        const reason = typeof error?.message === "string" && /^[a-z0-9_]+$/.test(error.message)
          ? error.message : "unexpected_oidc_error";
        console.error(JSON.stringify({ event: "oidc_callback_failed", reason }));
        const diagnostic = oidcConfig?.exposeSafeErrors ? `<p class="note">Code diagnostic : <code>${reason}</code></p>` : "";
        writeHtml(response, 400, "Connexion non validée", `<h1>Connexion non validée</h1><p>La preuve d’identité n’a pas pu être vérifiée. Aucun compte et aucun droit n’ont été modifiés.</p>${diagnostic}<a class="button" href="/">Retour</a>`, [clearTransaction]);
      }
      return;
    }
    if (url.pathname === "/auth/session" && request.method === "GET") {
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        const session = open(parseCookies(request.headers.cookie).get(OIDC_SESSION_COOKIE), oidcConfig.sessionSecret, "oidc-session");
        writeJson(response, 200, { authenticated: true, provider: "infomaniak", status: session.status, display_name: session.displayName });
      } catch { writeJson(response, 401, { authenticated: false }); }
      return;
    }
    if (url.pathname === "/auth/logout" && request.method === "POST") {
      response.statusCode = 303;
      response.setHeader("cache-control", "no-store");
      response.setHeader("location", "/");
      response.setHeader("set-cookie", cookie(OIDC_SESSION_COOKIE, "", { maxAge: 0 }));
      response.end();
      return;
    }
    if (url.pathname !== "/internal/v1/access-decisions") {
      writeJson(response, 404, { error: "resource_not_found" });
      return;
    }
    if (request.method !== "POST") {
      response.setHeader("allow", "POST");
      writeJson(response, 405, { error: "method_not_allowed" });
      return;
    }

    let correlationId = randomUUID();
    try {
      const payload = await readJson(request, maxBodyBytes);
      const principal = await authenticate(request);
      correlationId = principal?.correlationId || correlationId;
      const result = await evaluateAccessRequestAsync({ repository, principal, payload });
      writeJson(response, result.status, result.body, result.correlationId);
    } catch (error) {
      if (error instanceof HttpInputError) {
        writeJson(response, error.status, { error: error.code }, correlationId);
        return;
      }
      writeJson(response, 500, { error: "internal_error" }, correlationId);
    }
  };
}
