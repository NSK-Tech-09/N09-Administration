import { randomUUID, timingSafeEqual } from "node:crypto";
import { evaluateAccessRequestAsync } from "./api.mjs";
import { createAuditEvent } from "./audit.mjs";
import { createLinkRequest } from "./federated-identity.mjs";
import { authorizeAccessAdministration } from "./access-admin.mjs";
import { authorizeIdentityLinkAdministration } from "./identity-link-admin.mjs";
import {
  exchangeApplicationLoginCode, issueApplicationLoginCode, validateAuthorizationRequest,
} from "./application-login.mjs";
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
  response.end(`<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)} · N09 Administration</title><style>*{box-sizing:border-box}body{margin:0;background:#f3f6f4;color:#18221e;font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;padding:28px 0}.card{width:min(1100px,calc(100% - 36px));background:#fff;border:1px solid #dfe6e2;border-radius:18px;padding:34px;box-shadow:0 12px 40px #19392d14}.brand{color:#21825e;font-size:12px;font-weight:800;letter-spacing:1px}h1{font:600 31px Georgia,serif;margin:22px 0 12px}h2{font:600 21px Georgia,serif;margin:30px 0 12px}h3{margin:0 0 8px;font-size:17px}p{color:#5d6c65;line-height:1.6}.facts,.request{padding:16px;border-radius:10px;background:#f3f7f5;margin:20px 0}.facts strong,.request strong{color:#173e32}.button,button{display:inline-block;border:0;padding:12px 17px;border-radius:9px;background:#173e32;color:#fff;text-decoration:none;font-weight:bold;cursor:pointer}.button.secondary,button.secondary{background:#68756f}.actions{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:15px}.actions form{display:grid;gap:9px}.actions label{font-size:13px;font-weight:700}.actions select,.actions input{width:100%;padding:10px;border:1px solid #bdcac4;border-radius:8px;background:#fff}.note,.muted{font-size:13px;color:#6c7a74}.expired{color:#9b391f;font-weight:700}nav{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:22px}.summary{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:24px 0}.metric{padding:18px;border:1px solid #dce6e1;border-radius:12px;background:#f8faf9}.metric strong{display:block;font-size:28px;color:#173e32}.directory{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.entry{padding:17px;border:1px solid #dce6e1;border-radius:12px}.entry p{margin:7px 0}.pill{display:inline-block;padding:4px 8px;border-radius:999px;background:#e4f3ec;color:#176044;font-size:12px;font-weight:800}.pill.inactive{background:#f2e8e4;color:#8a3b28}.permissions{margin:8px 0 0;padding-left:19px;color:#45564f}.permissions code,code{font-size:12px;word-break:break-word}.assignment{border-left:4px solid #21825e} @media(max-width:700px){.actions,.directory,.summary{grid-template-columns:1fr}.card{padding:24px}}</style></head><body><main class="card"><div class="brand">N09 · ADMINISTRATION · NSK TECH 09</div>${content}</main></body></html>`);
}

async function readBody(request, maxBodyBytes) {
  const chunks = [];
  let received = 0;
  for await (const chunk of request) {
    received += chunk.length;
    if (received > maxBodyBytes) throw new HttpInputError(413, "request_too_large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function readJson(request, maxBodyBytes) {
  const contentType = request.headers["content-type"] ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new HttpInputError(415, "unsupported_media_type");
  }

  try {
    const rawBody = await readBody(request, maxBodyBytes);
    return { payload: JSON.parse(rawBody), rawBody };
  } catch (error) {
    if (error instanceof HttpInputError) throw error;
    throw new HttpInputError(400, "invalid_json");
  }
}

async function readForm(request, maxBodyBytes) {
  const contentType = request.headers["content-type"] ?? "";
  if (!contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    throw new HttpInputError(415, "unsupported_media_type");
  }
  return new URLSearchParams(await readBody(request, maxBodyBytes));
}

function safeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function redirect(response, location) {
  response.statusCode = 303;
  response.setHeader("cache-control", "no-store");
  response.setHeader("location", location);
  response.end();
}

function safeLoginReturnPath(value) {
  if (typeof value !== "string" || !value.startsWith("/application-login/authorize?") || value.includes("\r") || value.includes("\n")) return null;
  const parsed = new URL(value, "https://n09.invalid");
  return parsed.origin === "https://n09.invalid" ? `${parsed.pathname}${parsed.search}` : null;
}

function formatDate(value) {
  return new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Paris" }).format(new Date(value));
}

function renderLinkRequestAdministration(requests, identities, csrf, now = new Date()) {
  const identityOptions = identities.map((identity) =>
    `<option value="${escapeHtml(identity.identityId)}">${escapeHtml(identity.displayName)} — ${escapeHtml(identity.email)}</option>`
  ).join("");
  const cards = requests.map((request) => {
    const expired = new Date(request.expiresAt) <= now;
    const approval = expired ? '<p class="expired">Cette demande est expirée et ne peut plus être approuvée.</p>' :
      `<form method="post" action="/admin/link-requests/${escapeHtml(request.requestId)}/approve"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><label>Identité NSK cible<select name="target_identity_id" required><option value="">Sélectionner…</option>${identityOptions}</select></label><label>Justification<input name="justification" maxlength="500" required placeholder="Pourquoi ce rattachement est légitime"></label><button type="submit">Approuver</button></form>`;
    return `<section class="request"><h2>${escapeHtml(request.displayNameHint || "Identité externe")}</h2><p><strong>Fournisseur :</strong> ${escapeHtml(request.providerKey)}<br><strong>Adresse présentée :</strong> ${escapeHtml(request.emailHint || "non communiquée")}<br><strong>Demandée le :</strong> ${escapeHtml(formatDate(request.requestedAt))}<br><strong>Échéance :</strong> ${escapeHtml(formatDate(request.expiresAt))}<br><span class="note">Référence : ${escapeHtml(request.requestId)}</span></p><div class="actions">${approval}<form method="post" action="/admin/link-requests/${escapeHtml(request.requestId)}/reject"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><label>Motif du refus<input name="justification" maxlength="500" required placeholder="Pourquoi cette demande est refusée"></label><button class="secondary" type="submit">Refuser</button></form></div></section>`;
  }).join("");
  return `<h1>Demandes de rattachement</h1><p>Chaque décision est nominative, justifiée et inscrite dans le journal d’audit. Aucun rôle ni droit applicatif n’est accordé par un rattachement.</p>${cards || '<div class="facts"><p>Aucune demande en attente.</p></div>'}<nav><a class="button secondary" href="/">Retour à l’accueil</a><form method="post" action="/auth/logout"><button class="secondary" type="submit">Fermer la session</button></form></nav>`;
}

function renderAccessAdministration(identities, applications, assignments) {
  const identityById = new Map(identities.map((identity) => [identity.identityId, identity]));
  const applicationById = new Map(applications.map((application) => [application.applicationId, application]));
  const activeAssignments = assignments.filter((assignment) => assignment.status === "active").length;
  const statusPill = (status) => `<span class="pill${status === "active" ? "" : " inactive"}">${escapeHtml(status)}</span>`;
  const identityCards = identities.map((identity) =>
    `<article class="entry"><h3>${escapeHtml(identity.displayName)}</h3><p>${escapeHtml(identity.email)}</p><p>${statusPill(identity.status)}</p><p class="muted">Identité : <code>${escapeHtml(identity.identityId)}</code></p></article>`
  ).join("");
  const applicationCards = applications.map((application) =>
    `<article class="entry"><h3>${escapeHtml(application.displayName)}</h3><p>${statusPill(application.status)} · inscription ${escapeHtml(application.registrationPolicy)}</p><p class="muted">Application : <code>${escapeHtml(application.applicationId)}</code></p></article>`
  ).join("");
  const assignmentCards = assignments.map((assignment) => {
    const identity = identityById.get(assignment.subjectId);
    const application = applicationById.get(assignment.applicationId);
    const scope = assignment.scopeType ? `${assignment.scopeType} : ${assignment.scopeId || "non défini"}` : "global";
    const permissions = assignment.permissions.map((permission) => `<li><code>${escapeHtml(permission)}</code></li>`).join("");
    return `<article class="entry assignment"><h3>${escapeHtml(identity?.displayName || assignment.subjectId)} → ${escapeHtml(application?.displayName || assignment.applicationId)}</h3><p><strong>${escapeHtml(assignment.roleId)}</strong> · ${statusPill(assignment.status)} · périmètre ${escapeHtml(scope)}</p><ul class="permissions">${permissions || "<li>Aucune permission</li>"}</ul><p class="muted">Motif : ${escapeHtml(assignment.reason || "non renseigné")} · version ${escapeHtml(assignment.version)}</p></article>`;
  }).join("");
  return `<h1>Utilisateurs et accès</h1><p>Vue centrale en lecture seule des identités, applications et affectations. Cette page n’accorde, ne modifie et ne révoque aucun droit.</p><div class="summary"><div class="metric"><strong>${identities.length}</strong>identités</div><div class="metric"><strong>${applications.length}</strong>applications</div><div class="metric"><strong>${activeAssignments}</strong>affectations actives</div></div><h2>Identités</h2><div class="directory">${identityCards || '<div class="facts"><p>Aucune identité enregistrée.</p></div>'}</div><h2>Applications</h2><div class="directory">${applicationCards || '<div class="facts"><p>Aucune application enregistrée.</p></div>'}</div><h2>Affectations</h2><div class="directory">${assignmentCards || '<div class="facts"><p>Aucune affectation enregistrée.</p></div>'}</div><nav><a class="button secondary" href="/">Retour à l’accueil</a><a class="button secondary" href="/admin/link-requests">Rattachements</a><form method="post" action="/auth/logout"><button class="secondary" type="submit">Fermer la session</button></form></nav>`;
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
    if (url.pathname === "/application-login/authorize" && request.method === "GET") {
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        const loginRequest = validateAuthorizationRequest(url.searchParams);
        let session;
        try { session = open(parseCookies(request.headers.cookie).get(OIDC_SESSION_COOKIE), oidcConfig.sessionSecret, "oidc-session"); } catch { /* login below */ }
        if (!session) {
          redirect(response, `/auth/infomaniak/start?return_to=${encodeURIComponent(`${url.pathname}${url.search}`)}`);
          return;
        }
        const { code } = await issueApplicationLoginCode({ repository, session, request: loginRequest });
        const callback = new URL(loginRequest.redirectUri);
        callback.searchParams.set("code", code);
        callback.searchParams.set("state", loginRequest.state);
        redirect(response, callback.toString());
      } catch (error) {
        const denied = error?.message === "application_access_denied";
        const invalid = ["invalid_authorization_request", "redirect_uri_not_allowed", "application_login_not_configured", "authentication_required"].includes(error?.message);
        const unavailable = !denied && !invalid;
        writeHtml(response, unavailable ? 503 : denied ? 403 : 400, "Connexion applicative refusée",
          `<h1>Connexion applicative refusée</h1><p>${unavailable ? "Le registre central n’est pas vérifiable pour le moment." : denied ? "Cette identité ne possède pas l’autorisation centrale requise." : "La demande de connexion n’est pas valide ou n’est pas enregistrée."} Aucun accès n’a été ouvert.</p><a class="button" href="/">Retour</a>`);
      }
      return;
    }
    if (url.pathname === "/internal/v1/application-login/token" && request.method === "POST") {
      let correlationId = randomUUID();
      try {
        const { payload, rawBody } = await readJson(request, maxBodyBytes);
        const principal = await authenticate(request, { rawBody });
        correlationId = principal?.correlationId || correlationId;
        const identity = await exchangeApplicationLoginCode({ repository, principal, payload });
        writeJson(response, 200, identity, correlationId);
      } catch (error) {
        if (error instanceof HttpInputError) writeJson(response, error.status, { error: error.code }, correlationId);
        else if (error?.message === "invalid_technical_client") writeJson(response, 401, { error: "authentication_required" }, correlationId);
        else if (["invalid_token_request", "invalid_or_consumed_code", "identity_not_active"].includes(error?.message)) {
          writeJson(response, 400, { error: "invalid_grant" }, correlationId);
        } else writeJson(response, 503, { error: "identity_service_unavailable" }, correlationId);
      }
      return;
    }
    if (url.pathname === "/" && request.method === "GET") {
      let session = null;
      if (oidcConfig) {
        try { session = open(parseCookies(request.headers.cookie).get(OIDC_SESSION_COOKIE), oidcConfig.sessionSecret, "oidc-session"); } catch { /* anonymous */ }
      }
      const requestReference = session?.requestId
        ? `<p>Demande enregistrée : <strong>${escapeHtml(session.requestId)}</strong></p>` : "";
      const administrationLinks = [];
      if (session?.status === "authenticated" && session.csrf) {
        try {
          const decision = await authorizeIdentityLinkAdministration(repository, session.identityId);
          if (decision.allowed) administrationLinks.push('<a class="button" href="/admin/link-requests">Administrer les rattachements</a>');
        } catch { /* no administrative affordance on repository failure */ }
        try {
          const decision = await authorizeAccessAdministration(repository, session.identityId);
          if (decision.allowed) administrationLinks.push('<a class="button" href="/admin/access">Consulter les utilisateurs et accès</a>');
        } catch { /* no administrative affordance on repository failure */ }
      }
      const content = session
        ? `<h1>Identité Infomaniak vérifiée</h1><p>Bienvenue <strong>${escapeHtml(session.displayName)}</strong>. La preuve cryptographique est valide.</p><div class="facts"><p>État NSK : <strong>${session.status === "authenticated" ? "rattachée" : "rattachement requis"}</strong></p>${requestReference}<p>${session.status === "authenticated" ? "Le compte NSK est reconnu ; les droits restent contrôlés séparément." : "Aucun compte, rôle ou droit n’a été créé automatiquement. Une décision humaine reste obligatoire."}</p></div><nav>${administrationLinks.join("")}<form method="post" action="/auth/logout"><button class="secondary" type="submit">Fermer la session</button></form></nav>`
        : `<h1>Le cœur d’identité est prêt</h1><p>Connecte-toi avec Infomaniak pour présenter une preuve d’identité au registre central NSK.</p><div class="facts"><p><strong>Connexion réelle :</strong> Authorization Code + PKCE S256.</p><p><strong>Zéro privilège implicite :</strong> une identité inconnue reste sans droit.</p></div>${oidcConfig ? '<a class="button" href="/auth/infomaniak/start">Continuer avec Infomaniak</a>' : '<p>Le fournisseur OIDC n’est pas encore configuré.</p>'}`;
      writeHtml(response, 200, "Accueil", content);
      return;
    }
    if (url.pathname === "/auth/infomaniak/start" && request.method === "GET") {
      if (!oidcConfig) { writeJson(response, 503, { error: "oidc_not_configured" }); return; }
      const { url: authorizationUrl, transaction } = authorizationRequest(oidcConfig);
      const returnTo = safeLoginReturnPath(url.searchParams.get("return_to"));
      if (returnTo) transaction.returnTo = returnTo;
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
        const linked = await repository.findExternalIdentity(INFOMANIAK_ISSUER, claims.sub);
        let session;
        if (linked) {
          if (linked.status !== "active") throw new Error("external_identity_not_active");
          const identity = await repository.getIdentity(linked.identityId);
          if (!identity || identity.status !== "active") throw new Error("nsk_identity_not_active");
          session = {
            issuer: INFOMANIAK_ISSUER, subject: claims.sub, identityId: identity.identityId,
            displayName: identity.displayName, status: "authenticated", csrf: randomUUID(),
            expiresAt: Date.now() + 8 * 60 * 60 * 1000,
          };
        } else {
          const now = new Date();
          let linkRequest = await repository.findActiveLinkRequest(INFOMANIAK_ISSUER, claims.sub, now);
          if (!linkRequest) {
            linkRequest = createLinkRequest({
              issuer: INFOMANIAK_ISSUER, subject: claims.sub, providerKey: "infomaniak",
              emailHint: claims.email, displayNameHint: displayName, now,
            });
            await repository.saveLinkRequest(linkRequest, createAuditEvent({
              action: "external_identity.link_requested", result: "pending",
              source: "infomaniak-callback", correlationId: randomUUID(),
              newValue: { request_id: linkRequest.requestId, status: "pending", expires_at: linkRequest.expiresAt },
            }));
          }
          session = {
            issuer: INFOMANIAK_ISSUER, subject: claims.sub, displayName,
            status: "link_required", requestId: linkRequest.requestId,
            requestExpiresAt: linkRequest.expiresAt,
            expiresAt: Date.now() + 8 * 60 * 60 * 1000,
          };
        }
        const sessionCookie = cookie(OIDC_SESSION_COOKIE, seal(session, oidcConfig.sessionSecret, "oidc-session"), { maxAge: 8 * 60 * 60 });
        response.statusCode = 303;
        response.setHeader("cache-control", "no-store");
        response.setHeader("location", session.status === "authenticated" && transaction.returnTo ? transaction.returnTo : "/");
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
        writeJson(response, 200, {
          authenticated: true, provider: "infomaniak", status: session.status,
          display_name: session.displayName, request_id: session.requestId ?? null,
        });
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
    if (url.pathname === "/admin/access") {
      if (request.method !== "GET") {
        response.setHeader("allow", "GET");
        writeJson(response, 405, { error: "method_not_allowed" });
        return;
      }
      let session;
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        session = open(parseCookies(request.headers.cookie).get(OIDC_SESSION_COOKIE), oidcConfig.sessionSecret, "oidc-session");
      } catch {
        writeHtml(response, 401, "Connexion requise", '<h1>Connexion requise</h1><p>Une session NSK valide est nécessaire.</p><a class="button" href="/">Se connecter</a>');
        return;
      }
      if (session.status !== "authenticated" || !session.identityId || !session.csrf) {
        writeHtml(response, 401, "Nouvelle connexion requise", '<h1>Nouvelle connexion requise</h1><p>Ferme puis renouvelle ta session afin d’accéder à l’administration sécurisée.</p><a class="button" href="/">Retour</a>');
        return;
      }
      let access;
      try {
        access = await authorizeAccessAdministration(repository, session.identityId);
      } catch {
        console.error(JSON.stringify({ event: "access_administration_unavailable", reason: "authorization_repository_failure" }));
        writeHtml(response, 503, "Administration indisponible", '<h1>Administration momentanément indisponible</h1><p>Aucune donnée d’accès ne peut être vérifiée pour le moment.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (!access.allowed) {
        writeHtml(response, 403, "Accès refusé", '<h1>Accès refusé</h1><p>Cette identité ne possède pas la permission dédiée à la consultation des accès. Aucun droit implicite n’est accordé.</p><a class="button" href="/">Retour</a>');
        return;
      }
      try {
        const [identities, applications, assignments] = await Promise.all([
          repository.listIdentities(), repository.listApplications(), repository.listAllAssignments(),
        ]);
        writeHtml(response, 200, "Utilisateurs et accès", renderAccessAdministration(identities, applications, assignments));
      } catch {
        console.error(JSON.stringify({ event: "access_administration_unavailable", reason: "listing_repository_failure" }));
        writeHtml(response, 503, "Administration indisponible", '<h1>Administration momentanément indisponible</h1><p>Le registre n’a pas pu être consulté. Aucun accès n’a été modifié.</p><a class="button" href="/">Retour</a>');
      }
      return;
    }
    const adminRoute = url.pathname.match(/^\/admin\/link-requests(?:\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/(approve|reject))?$/i);
    if (adminRoute) {
      let session;
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        session = open(parseCookies(request.headers.cookie).get(OIDC_SESSION_COOKIE), oidcConfig.sessionSecret, "oidc-session");
      } catch {
        writeHtml(response, 401, "Connexion requise", '<h1>Connexion requise</h1><p>Une session NSK valide est nécessaire.</p><a class="button" href="/">Se connecter</a>');
        return;
      }
      if (session.status !== "authenticated" || !session.identityId || !session.csrf) {
        writeHtml(response, 401, "Nouvelle connexion requise", '<h1>Nouvelle connexion requise</h1><p>Ferme puis renouvelle ta session afin d’accéder à l’administration sécurisée.</p><a class="button" href="/">Retour</a>');
        return;
      }
      let access;
      try {
        access = await authorizeIdentityLinkAdministration(repository, session.identityId);
      } catch {
        console.error(JSON.stringify({ event: "link_administration_unavailable", reason: "authorization_repository_failure" }));
        writeHtml(response, 503, "Administration indisponible", '<h1>Administration momentanément indisponible</h1><p>Aucune décision n’a été appliquée. Réessaie lorsque le registre central sera disponible.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (!access.allowed) {
        writeHtml(response, 403, "Accès refusé", '<h1>Accès refusé</h1><p>Cette identité ne possède pas la permission administrative dédiée. Aucun droit implicite n’est accordé.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (!adminRoute[1] && request.method === "GET") {
        try {
          const [requests, identities] = await Promise.all([
            repository.listLinkRequests("pending"), repository.listIdentities("active"),
          ]);
          writeHtml(response, 200, "Rattachements", renderLinkRequestAdministration(requests, identities, session.csrf));
        } catch {
          console.error(JSON.stringify({ event: "link_administration_unavailable", reason: "listing_repository_failure" }));
          writeHtml(response, 503, "Administration indisponible", '<h1>Administration momentanément indisponible</h1><p>Le registre n’a pas pu être consulté. Aucune décision n’a été appliquée.</p><a class="button" href="/">Retour</a>');
        }
        return;
      }
      if (adminRoute[1] && request.method === "POST") {
        try {
          const form = await readForm(request, maxBodyBytes);
          if (!safeEqual(form.get("csrf"), session.csrf)) throw new HttpInputError(403, "invalid_csrf");
          const requestId = adminRoute[1].toLowerCase();
          const decision = adminRoute[2].toLowerCase();
          const justification = String(form.get("justification") ?? "").trim();
          if (!justification || justification.length > 500) throw new HttpInputError(400, "invalid_justification");
          const linkRequest = await repository.getLinkRequest(requestId);
          if (!linkRequest) throw new HttpInputError(404, "link_request_not_found");
          const correlationId = randomUUID();
          if (decision === "approve") {
            const targetIdentityId = String(form.get("target_identity_id") ?? "").trim();
            if (!targetIdentityId) throw new HttpInputError(400, "target_identity_required");
            await repository.approveLinkRequest(requestId, targetIdentityId, session.identityId, justification, createAuditEvent({
              action: "external_identity.link_approved", result: "success", source: "administration-ui",
              correlationId, actorId: session.identityId, subjectId: targetIdentityId,
              previousValue: { request_id: requestId, status: "pending" },
              newValue: { request_id: requestId, status: "approved", target_identity_id: targetIdentityId },
              justification,
            }));
          } else {
            await repository.rejectLinkRequest(requestId, session.identityId, justification, createAuditEvent({
              action: "external_identity.link_rejected", result: "success", source: "administration-ui",
              correlationId, actorId: session.identityId,
              previousValue: { request_id: requestId, status: "pending" },
              newValue: { request_id: requestId, status: "rejected" }, justification,
            }));
          }
          redirect(response, "/admin/link-requests");
        } catch (error) {
          if (error instanceof HttpInputError) {
            writeHtml(response, error.status, "Décision non appliquée", `<h1>Décision non appliquée</h1><p>La demande est invalide ou n’est plus disponible. Aucun changement partiel n’a été conservé.</p><p class="note">Code : ${escapeHtml(error.code)}</p><a class="button" href="/admin/link-requests">Retour</a>`);
          } else {
            console.error(JSON.stringify({ event: "link_decision_failed", reason: "repository_rejected_decision" }));
            writeHtml(response, 409, "Décision non appliquée", '<h1>Décision non appliquée</h1><p>La demande ne peut pas être traitée dans son état actuel. Aucun changement partiel n’a été conservé.</p><a class="button" href="/admin/link-requests">Retour</a>');
          }
        }
        return;
      }
      response.setHeader("allow", adminRoute[1] ? "POST" : "GET");
      writeJson(response, 405, { error: "method_not_allowed" });
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
      const { payload, rawBody } = await readJson(request, maxBodyBytes);
      const principal = await authenticate(request, { rawBody });
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
