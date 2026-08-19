import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { evaluateAccessRequestAsync } from "./api.mjs";
import { createAuditEvent } from "./audit.mjs";
import { publishApplicationAccessCatalog } from "./application-access-catalog.mjs";
import { applicationDisplayName } from "./application-display-name.mjs";
import { receiveNotificationEvents } from "./notification-ingress.mjs";
import { createLinkRequest } from "./federated-identity.mjs";
import {
  consumeEmailLogin, EmailLoginError, EMAIL_LOGIN_ISSUER, EMAIL_LOGIN_PROVIDER,
  inspectEmailLogin, requestEmailLogin,
} from "./email-login.mjs";
import { authorizeAccessAdministration } from "./access-admin.mjs";
import {
  ACCESS_DECISION_PERMISSION, authorizeAccessDecisionAdministration, grantAccessAssignment, revokeAccessAssignment,
} from "./access-decision-admin.mjs";
import {
  AccessRequestError, approveAccessRequestLine, refuseAccessRequestLine, submitPublicAccessRequest,
} from "./access-request.mjs";
import { ADMIN_APPLICATION_ID, authorizeIdentityLinkAdministration } from "./identity-link-admin.mjs";
import { authorizeNotificationOperationsAdministration } from "./notification-operations-admin.mjs";
import { PersonalSessionError } from "./personal-session-management.mjs";
import {
  authorizeSessionRevocationAdministration, OperatorSessionError,
} from "./operator-session-management.mjs";
import {
  authorizeIdentityLifecycleAdministration, IdentityStateError,
} from "./identity-state-management.mjs";
import { assessResponsibleAuthority } from "./responsible-authority.mjs";
import {
  exchangeApplicationLoginCode, issueApplicationLoginCode, validateAuthorizationRequest,
} from "./application-login.mjs";
import {
  authorizationRequest, cookie, exchangeAuthorizationCode, INFOMANIAK_ISSUER,
  OIDC_SESSION_COOKIE, OIDC_TRANSACTION_COOKIE, open, parseCookies, seal, verifyIdToken,
} from "./oidc.mjs";
import {
  issuePortalSession, openPortalSession, portalDirectory, PORTAL_SESSION_COOKIE,
  revokePortalSession, safePortalReturn,
} from "./portal-session-broker.mjs";

const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const CURRENT_SESSION_VERSION = 2;
const EMAIL_LOGIN_CONFIRMATION_COOKIE = "n09_email_login_confirmation";
const ADMIN_VERSION = "0.2.10";
const STATIC_ASSETS = new Map([
  ["/assets/nsktech09-logo-master.png", { type: "image/png", body: readFileSync(new URL("./assets/nsktech09-logo-master.png", import.meta.url)) }],
  ["/assets/Manrope-VariableFont_wght.ttf", { type: "font/ttf", body: readFileSync(new URL("./assets/Manrope-VariableFont_wght.ttf", import.meta.url)) }],
  ["/assets/favicon.ico", { type: "image/x-icon", body: readFileSync(new URL("./assets/favicon.ico", import.meta.url)) }],
  ["/assets/theme.js", { type: "text/javascript; charset=utf-8", body: readFileSync(new URL("./assets/theme.js", import.meta.url)) }],
]);

function setSecurityHeaders(response) {
  response.setHeader("strict-transport-security", "max-age=31536000; includeSubDomains");
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("x-frame-options", "DENY");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=()");
}

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
  response.setHeader("content-security-policy", "default-src 'none'; img-src 'self'; font-src 'self'; script-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("x-content-type-options", "nosniff");
  if (setCookies.length) response.setHeader("set-cookie", setCookies);
  response.end(`<!doctype html><html lang="fr" data-theme="system"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)} · N09 Administration</title><link rel="icon" href="/assets/favicon.ico"><style>[hidden]{display:none!important}@font-face{font-family:Manrope;src:url('/assets/Manrope-VariableFont_wght.ttf') format('truetype');font-weight:200 800;font-display:swap}:root{--bg:#f4f7f6;--panel:#fff;--muted-bg:#e8efec;--line:#cad6d2;--text:#1a3746;--muted:#52666f;--brand:#0d9376;--brand-strong:#08745e;--link:#08745e;--shadow:#1a37461f;color-scheme:light}html[data-theme=gray]{--bg:#363a3c;--panel:#484d4f;--muted-bg:#3f4446;--line:#707678;--text:#f4f6f5;--muted:#d4d9d7;--brand:#62d9bf;--brand-strong:#0d9376;--link:#75d5e8;--shadow:#0005;color-scheme:dark}html[data-theme=dark]{--bg:#101719;--panel:#172123;--muted-bg:#223034;--line:#385156;--text:#f4f8f8;--muted:#aebfc2;--brand:#62d9bf;--brand-strong:#0d9376;--link:#65d0df;--shadow:#0006;color-scheme:dark}@media(prefers-color-scheme:dark){html[data-theme=system]{--bg:#101719;--panel:#172123;--muted-bg:#223034;--line:#385156;--text:#f4f8f8;--muted:#aebfc2;--brand:#62d9bf;--brand-strong:#0d9376;--link:#65d0df;--shadow:#0006;color-scheme:dark}}*{box-sizing:border-box}html{background:var(--bg)}body{margin:0;background:var(--bg);color:var(--text);font:16px Manrope,system-ui,sans-serif;min-height:100vh}.skip{position:fixed;left:12px;top:-80px;z-index:10;background:var(--brand-strong);color:#fff;padding:10px 14px;border-radius:8px}.skip:focus{top:12px}.app-header{display:flex;align-items:center;gap:18px;padding:16px max(18px,calc((100% - 1100px)/2));border-bottom:1px solid var(--line);background:var(--panel)}.logo-link{display:flex;align-items:center;min-width:74px;min-height:62px}.logo{width:78px;height:58px;object-fit:contain}.identity{min-width:0}.brand{color:var(--brand);font-size:12px;font-weight:800;letter-spacing:1.5px}.identity strong{display:block;font-size:20px}.header-actions{margin-left:auto;display:flex;align-items:center;gap:8px;flex-wrap:wrap}.quick{display:flex;align-items:end;gap:14px;padding:10px max(18px,calc((100% - 1100px)/2));border-bottom:1px solid var(--line);background:var(--panel)}.quick label{display:grid;gap:4px;color:var(--muted);font-size:12px}.quick select{min-height:42px;padding:8px 36px 8px 11px;border:1px solid var(--line);border-radius:9px;background:var(--panel);color:var(--text);font:inherit}.card{width:min(1100px,calc(100% - 36px));margin:28px auto;background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:34px;box-shadow:0 12px 40px var(--shadow)}h1{font-size:31px;line-height:1.2;margin:22px 0 12px}h2{font-size:21px;margin:30px 0 12px}h3{margin:0 0 8px;font-size:17px}p{color:var(--muted);line-height:1.6}.facts,.request{padding:16px;border-radius:10px;background:var(--muted-bg);margin:20px 0}.facts strong,.request strong{color:var(--text)}a{color:var(--link)}.button,button{display:inline-block;border:1px solid transparent;padding:12px 17px;border-radius:9px;background:var(--brand-strong);color:#fff;text-decoration:none;font:inherit;font-weight:750;cursor:pointer}.button.secondary,button.secondary{background:var(--muted-bg);border-color:var(--line);color:var(--text)}button:hover,.button:hover{filter:brightness(1.07)}a:focus-visible,button:focus-visible,select:focus-visible,input:focus-visible{outline:3px solid var(--link);outline-offset:3px}.actions{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:15px}.actions form,.grant{display:grid;gap:9px}.actions label,.grant label{font-size:13px;font-weight:700}.actions select,.actions input,.grant select,.grant input{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--text)}.note,.muted{font-size:13px;color:var(--muted)}.expired{color:#b24a31;font-weight:700}nav{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:22px}.summary{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:24px 0}.metric{padding:18px;border:1px solid var(--line);border-radius:12px;background:var(--muted-bg)}.metric strong{display:block;font-size:28px;color:var(--text)}.directory{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.entry{padding:17px;border:1px solid var(--line);border-radius:12px}.entry p{margin:7px 0}.pill{display:inline-block;padding:4px 8px;border-radius:999px;background:#dff4ec;color:#176044;font-size:12px;font-weight:800}.pill.inactive{background:#f2e8e4;color:#8a3b28}.permissions{margin:8px 0 0;padding-left:19px;color:var(--muted)}.permissions code,code{font-size:12px;word-break:break-word}.assignment{border-left:4px solid var(--brand)}footer{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;width:min(1100px,calc(100% - 36px));margin:0 auto;padding:8px 0 28px;color:var(--muted);font-size:13px}footer nav{margin:0}footer a{text-decoration:underline}@media(max-width:700px){.actions,.directory,.summary{grid-template-columns:1fr}.card{padding:24px}.app-header,.quick{align-items:flex-start;flex-wrap:wrap}.header-actions{width:100%;margin-left:0}.quick label{width:100%}.quick select{width:100%}footer{display:grid}}</style><script src="/assets/theme.js?v=0.2.4" defer></script></head><body><a class="skip" href="#contenu">Aller au contenu</a><header class="app-header"><a class="logo-link" href="https://nsktech.fr/" target="_blank" rel="noopener noreferrer" aria-label="Ouvrir le portail NSK Tech 09 dans un nouvel onglet"><img class="logo" src="/assets/nsktech09-logo-master.png" alt="NSK Tech 09"></a><div class="identity"><span class="brand">NSK TECH 09</span><strong>N09 – Administration</strong><span>Identités et accès</span></div><div class="header-actions"><a class="button secondary" href="/account">Mon compte</a><form method="post" action="/auth/logout"><button class="secondary" type="submit">Se déconnecter</button></form></div></header><div class="quick"><label>Accès rapide<select id="nsk-quick-access" aria-label="Accès rapide"><option value="">Choisir une destination</option><option value="/">Accueil</option><option value="/account">Mon compte</option><option value="/notifications">Notifications</option></select></label><label>Thème<select id="nsk-theme" aria-label="Choisir le thème"><option value="system">Système</option><option value="light">Clair</option><option value="gray">Gris</option><option value="dark">Sombre</option></select></label></div><main id="contenu" class="card"><div class="brand">N09 · ADMINISTRATION · NSK TECH 09</div>${content}</main><footer><span>N09 – Administration · version ${ADMIN_VERSION} · application web installable</span><nav aria-label="Informations légales"><a href="https://nsktech.fr/#mentions-legales" target="_blank" rel="noopener noreferrer">Mentions légales</a><a href="https://nsktech.fr/#confidentialite" target="_blank" rel="noopener noreferrer">Confidentialité</a></nav><span>Comprendre. Concevoir. Transmettre.</span></footer></body></html>`);
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

function validOperatorTarget(target) {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return target && uuid.test(String(target.targetIdentityId ?? "")) &&
    uuid.test(String(target.targetSessionId ?? "")) &&
    Number.isSafeInteger(target.expectedVersion) && target.expectedVersion > 0;
}

function validIdentityStateTarget(target) {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return target && uuid.test(String(target.targetIdentityId ?? "")) &&
    ["active", "suspended"].includes(target.expectedStatus);
}

function redirect(response, location) {
  response.statusCode = 303;
  response.setHeader("cache-control", "no-store");
  response.setHeader("location", location);
  response.end();
}

function safeLoginReturnPath(value) {
  if (typeof value !== "string" || value.includes("\r") || value.includes("\n") ||
      (value !== "/" && !value.startsWith("/application-login/authorize?") &&
       !value.startsWith("/portal/login?") && !value.startsWith("/account?") &&
       !value.startsWith("/account/sessions?"))) return null;
  const parsed = new URL(value, "https://n09.invalid");
  return parsed.origin === "https://n09.invalid" ? `${parsed.pathname}${parsed.search}` : null;
}

function openEmailLoginConfirmation(value, sessionSecret) {
  try {
    return open(value, sessionSecret, "email-login-confirmation");
  } catch {
    throw new EmailLoginError("invalid_or_consumed_email_login");
  }
}

const ACCOUNT_APPLICATION_ORIGINS = Object.freeze([
  "https://energie.nsktech.fr",
  "https://preprod-energie.nsktech.fr",
  "https://prod-taches.nsktech.fr",
  "https://preprod-taches.nsktech.fr",
  "https://prod-admin.nsktech.fr",
  "https://preprod-admin.nsktech.fr",
]);

function safeAccountTheme(value) {
  return ["system", "light", "gray", "dark"].includes(value) ? value : "system";
}

function safeAccountReturn(value, portalOrigins, fallback) {
  if (typeof value !== "string" || value.includes("\r") || value.includes("\n")) return fallback;
  try {
    const target = new URL(value);
    const allowedOrigins = new Set([...portalOrigins, ...ACCOUNT_APPLICATION_ORIGINS]);
    return target.protocol === "https:" && allowedOrigins.has(target.origin) ? target.href : fallback;
  } catch {
    return fallback;
  }
}

function trustedPortalLogoutRequest(request) {
  if (request.headers["sec-fetch-site"] === "cross-site") return false;
  // La preuve réelle est le cookie hôte chiffré, HttpOnly, Secure et SameSite=Lax,
  // ouvert ensuite avant toute révocation. Origin et Referer restent indicatifs :
  // certains navigateurs ou filtres de confidentialité les retirent ou les réécrivent.
  const portalCookie = parseCookies(request.headers.cookie).get(PORTAL_SESSION_COOKIE);
  return typeof portalCookie === "string" && portalCookie.length > 0;
}

function renderPortalLogin({ returnTo, theme, localReturn = null, emailLoginEnabled = false }) {
  localReturn ||= `/portal/login?return_to=${encodeURIComponent(returnTo)}&theme=${encodeURIComponent(theme)}`;
  const infomaniakStart = `/auth/infomaniak/start?return_to=${encodeURIComponent(localReturn)}`;
  const emailProvider = emailLoginEnabled
    ? `<section class="entry assignment"><h3>Courriel <span class="pill">Disponible</span></h3><p>Reçois un lien unique, valable dix minutes, sans mot de passe NSK.</p><form class="grant" method="post" action="/auth/email/request"><input type="hidden" name="return_to" value="${escapeHtml(localReturn)}"><label for="email-login">Adresse associée à ton identité NSK</label><input id="email-login" name="email" type="email" maxlength="320" autocomplete="email" required><button type="submit">Recevoir mon lien</button></form></section>`
    : `<section class="entry"><h3>Courriel <span class="pill inactive">Prévu</span></h3><p>Lien de connexion unique, sans mot de passe local.</p><p class="note">Disponible après configuration et validation du canal d’envoi.</p></section>`;
  const plannedProviders = [
    ["Google", "Compte Google personnel ou professionnel"],
    ["Microsoft", "Compte Microsoft personnel ou professionnel"],
    ["GitHub", "Compte GitHub existant"],
  ].map(([name, description]) => `<section class="entry"><h3>${name} <span class="pill inactive">Prévu</span></h3><p>${description}</p><p class="note">Disponible après configuration et validation de sécurité.</p></section>`).join("");
  return `<h1>Se connecter à NSK Tech 09</h1><p>Choisis la méthode qui te convient. La méthode vérifie ton identité ; les droits restent exclusivement gérés par N09 – Administration.</p><div class="directory"><section class="entry assignment"><h3>Infomaniak <span class="pill">Disponible</span></h3><p>Utilise ton compte Infomaniak actuel.</p><a class="button" href="${escapeHtml(infomaniakStart)}">Continuer avec Infomaniak</a></section>${emailProvider}${plannedProviders}</div><div class="facts"><p><strong>Une seule identité NSK :</strong> toutes les méthodes reconnues conduisent au même compte central.</p><p><strong>Aucun droit implicite :</strong> une méthode de connexion ne donne accès à aucune application supplémentaire.</p><p><strong>Aucun mot de passe NSK :</strong> le courriel utilise un lien éphémère ; les autres mots de passe restent chez leur fournisseur.</p></div><nav><a class="button secondary" href="${escapeHtml(returnTo)}">Retour</a></nav>`;
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

function renderAccessAdministration(identities, applications, assignments, catalogs) {
  const identityById = new Map(identities.map((identity) => [identity.identityId, identity]));
  const applicationById = new Map(applications.map((application) => [application.applicationId, application]));
  const catalogByApplicationId = new Map(catalogs.map((catalog) => [catalog.applicationId, catalog]));
  const activeIdentities = identities.filter((identity) => identity.status === "active").length;
  const activeApplications = applications.filter((application) => application.status === "active").length;
  const activeAssignments = assignments.filter((assignment) => assignment.status === "active").length;
  const statusPill = (status) => `<span class="pill${status === "active" ? "" : " inactive"}">${escapeHtml(status)}</span>`;
  const identityCards = identities.map((identity) =>
    `<article class="entry"><h3>${escapeHtml(identity.displayName)}</h3><p>${escapeHtml(identity.email)}</p><p>${statusPill(identity.status)}</p><p class="muted">Identité : <code>${escapeHtml(identity.identityId)}</code></p></article>`
  ).join("");
  const applicationCards = applications.map((application) => {
    const catalog = catalogByApplicationId.get(application.applicationId);
    if (!catalog) return `<article class="entry"><h3>${escapeHtml(application.displayName)}</h3><p>${statusPill(application.status)} · inscription ${escapeHtml(application.registrationPolicy)}</p><div class="facts"><p><strong>Catalogue absent :</strong> aucun nouvel octroi ne doit être ouvert pour cette application.</p></div><p class="muted">Application : <code>${escapeHtml(application.applicationId)}</code></p></article>`;
    const roles = catalog.roles.map((role) => `<li><code>${escapeHtml(role.role_id)}</code> — ${escapeHtml(role.displayName)} (${escapeHtml(role.status)})</li>`).join("");
    const provisioning = catalog.provisioning.mode === "central_identity_only"
      ? "identité centrale, sans profil applicatif supplémentaire"
      : catalog.provisioning.mode === "preexisting_profile_required"
        ? "profil applicatif préexistant et confirmation de l’application requis"
        : "création automatique déclarée par l’application";
    return `<article class="entry"><h3>${escapeHtml(application.displayName)}</h3><p>${statusPill(application.status)} · inscription ${escapeHtml(application.registrationPolicy)}</p><p><strong>Catalogue v${escapeHtml(catalog.catalogVersion)}</strong> · ${escapeHtml(provisioning)}</p><ul class="permissions">${roles}</ul><p class="muted">Application : <code>${escapeHtml(application.applicationId)}</code><br>Empreinte : <code>${escapeHtml(catalog.catalogHash)}</code></p></article>`;
  }).join("");
  const assignmentCards = assignments.map((assignment) => {
    const identity = identityById.get(assignment.subjectId);
    const application = applicationById.get(assignment.applicationId);
    const scope = assignment.scopeType ? `${assignment.scopeType} : ${assignment.scopeId || "non défini"}` : "global";
    const permissions = assignment.permissions.map((permission) => `<li><code>${escapeHtml(permission)}</code></li>`).join("");
    return `<article class="entry assignment"><h3>${escapeHtml(identity?.displayName || assignment.subjectId)} → ${escapeHtml(application?.displayName || assignment.applicationId)}</h3><p><strong>${escapeHtml(assignment.roleId)}</strong> · ${statusPill(assignment.status)} · périmètre ${escapeHtml(scope)}</p><ul class="permissions">${permissions || "<li>Aucune permission</li>"}</ul><p class="muted">Motif : ${escapeHtml(assignment.reason || "non renseigné")} · version ${escapeHtml(assignment.version)}</p></article>`;
  }).join("");
  return `<h1>Utilisateurs et accès</h1><p>Vue centrale en lecture seule des identités, applications, catalogues publiés et affectations. Cette page n’accorde, ne modifie et ne révoque aucun droit.</p><div class="summary"><div class="metric"><strong>${activeIdentities}</strong>identités actives</div><div class="metric"><strong>${activeApplications}</strong>applications actives</div><div class="metric"><strong>${activeAssignments}</strong>affectations actives</div></div><h2>Identités</h2><div class="directory">${identityCards || '<div class="facts"><p>Aucune identité enregistrée.</p></div>'}</div><h2>Applications et catalogues</h2><div class="directory">${applicationCards || '<div class="facts"><p>Aucune application enregistrée.</p></div>'}</div><h2>Affectations</h2><div class="directory">${assignmentCards || '<div class="facts"><p>Aucune affectation enregistrée.</p></div>'}</div><nav><a class="button secondary" href="/">Retour à l’accueil</a><a class="button secondary" href="/admin/link-requests">Rattachements</a><form method="post" action="/auth/logout"><button class="secondary" type="submit">Fermer la session</button></form></nav>`;
}

function renderAccessDecisionAdministration(identities, applications, assignments, catalogs, csrf) {
  const identityById = new Map(identities.map((identity) => [identity.identityId, identity]));
  const applicationById = new Map(applications.map((application) => [application.applicationId, application]));
  const activeIdentityOptions = identities.filter((identity) => identity.status === "active").map((identity) =>
    `<option value="${escapeHtml(identity.identityId)}">${escapeHtml(identity.displayName)} — ${escapeHtml(identity.email)}</option>`
  ).join("");
  const grantCards = catalogs.filter((catalog) => catalog.applicationId !== ADMIN_APPLICATION_ID).flatMap((catalog) => {
    const application = applicationById.get(catalog.applicationId);
    if (!application || application.status !== "active") return [];
    const activeScopeTypes = new Map(catalog.scopeTypes.filter((scope) => scope.status === "active")
      .map((scope) => [scope.scope_type_id, scope]));
    const requirements = catalog.provisioning.readiness === "application_confirmation_required"
      ? catalog.provisioning.requirements : [];
    return catalog.roles.filter((role) => role.status === "active").flatMap((role) =>
      role.scopeTypes.filter((scopeType) => activeScopeTypes.has(scopeType)).map((scopeType) => {
        const scope = activeScopeTypes.get(scopeType);
        const scopeInput = scopeType === "global"
          ? '<input type="hidden" name="scope_type" value="global"><p><strong>Périmètre :</strong> global</p>'
          : `<input type="hidden" name="scope_type" value="${escapeHtml(scopeType)}"><label>${escapeHtml(scope.displayName)}<input name="scope_id" maxlength="191" required placeholder="Identifiant exact fourni par l’application"></label>`;
        const requirementItems = requirements.map((requirement) =>
          `<li><code>${escapeHtml(requirement.requirement_id)}</code> — ${escapeHtml(requirement.displayName)}</li>`
        ).join("");
        const readiness = requirementItems
          ? `<div class="facts"><p><strong>Activation conditionnelle :</strong> l’application devra confirmer à chaque requête :</p><ul class="permissions">${requirementItems}</ul></div>`
          : '<div class="facts"><p><strong>Activation immédiate :</strong> aucun profil applicatif supplémentaire n’est déclaré.</p></div>';
        return `<article class="entry"><h3>${escapeHtml(application.displayName)} — ${escapeHtml(role.displayName)}</h3><p>${escapeHtml(role.description)}</p>${readiness}<form class="grant" method="post" action="/admin/access-decisions/grant"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="application_id" value="${escapeHtml(catalog.applicationId)}"><input type="hidden" name="catalog_version" value="${escapeHtml(catalog.catalogVersion)}"><input type="hidden" name="role_id" value="${escapeHtml(role.role_id)}"><label>Personne autorisée<select name="identity_id" required><option value="">Sélectionner…</option>${activeIdentityOptions}</select></label>${scopeInput}<label>Justification<input name="justification" minlength="20" maxlength="500" required placeholder="Pourquoi cet accès est-il nécessaire ?"></label><button type="submit">Accorder cet accès conditionnel</button></form></article>`;
      })
    );
  }).join("");
  const activeAssignments = assignments.filter((assignment) => assignment.status === "active");
  const cards = activeAssignments.map((assignment) => {
    const identity = identityById.get(assignment.subjectId);
    const application = applicationById.get(assignment.applicationId);
    const scope = assignment.scopeType ? `${assignment.scopeType} : ${assignment.scopeId || "non défini"}` : "global";
    const permissions = assignment.permissions.map((permission) => `<li><code>${escapeHtml(permission)}</code></li>`).join("");
    const protectedAuthority = assignment.applicationId === ADMIN_APPLICATION_ID
      && assignment.permissions.includes(ACCESS_DECISION_PERMISSION);
    const action = protectedAuthority
      ? '<div class="facts"><p><strong>Pouvoir protégé :</strong> son passage de relais relève d’une procédure de gouvernance dédiée.</p></div>'
      : `<div class="actions"><form method="post" action="/admin/access-decisions/${escapeHtml(assignment.assignmentId)}/revoke"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="expected_version" value="${escapeHtml(assignment.version)}"><label>Justification de la révocation<input name="justification" minlength="20" maxlength="500" required placeholder="Pourquoi cet accès doit-il être retiré ?"></label><button class="secondary" type="submit">Révoquer cet accès</button></form></div>`;
    return `<article class="entry assignment"><h2>${escapeHtml(identity?.displayName || assignment.subjectId)} → ${escapeHtml(application?.displayName || assignment.applicationId)}</h2><p><strong>${escapeHtml(assignment.roleId)}</strong> · périmètre ${escapeHtml(scope)} · version ${escapeHtml(assignment.version)}</p><ul class="permissions">${permissions}</ul>${action}</article>`;
  }).join("");
  return `<h1>Décider les accès</h1><p>Un octroi ne peut utiliser qu’un rôle actif publié par l’application. Son périmètre, sa justification et ses conditions sont inscrits dans le journal d’audit. Une application qui exige un profil métier doit ensuite confirmer ses propres prérequis à chaque requête.</p><div class="facts"><p><strong>Séparation stricte :</strong> Administration accorde le droit central ; l’application conserve et vérifie le rôle métier et le périmètre local. Le pouvoir de décision central reste soumis à sa gouvernance dédiée.</p></div><h2>Accorder un accès gouverné</h2><div class="directory">${grantCards || '<div class="facts"><p>Aucun rôle applicatif actif n’est actuellement ouvert à l’octroi.</p></div>'}</div><h2>Révoquer un accès actif</h2><div class="directory">${cards || '<div class="facts"><p>Aucune affectation active.</p></div>'}</div><nav><a class="button secondary" href="/admin/access">Retour au registre</a><a class="button secondary" href="/">Retour à l’accueil</a><form method="post" action="/auth/logout"><button class="secondary" type="submit">Fermer la session</button></form></nav>`;
}

function renderAccessRequestAdministration(requests, identities, catalogs, csrf) {
  const activeIdentityOptions = identities.filter((identity) => identity.status === "active").map((identity) =>
    `<option value="${escapeHtml(identity.identityId)}">${escapeHtml(identity.displayName)} — ${escapeHtml(identity.email)}</option>`
  ).join("");
  const catalogByApplication = new Map(catalogs.map((catalog) => [catalog.applicationId, catalog]));
  const requestCards = requests.map((accessRequest) => {
    const lines = accessRequest.lines.map((line) => {
      const catalog = catalogByApplication.get(line.applicationId);
      if (line.status !== "pending") {
        return `<article class="entry"><h3>${escapeHtml(line.applicationName)}</h3><p><span class="pill${line.status === "approved" ? "" : " inactive"}">${escapeHtml(line.status)}</span></p><p class="muted">Décision : ${escapeHtml(line.decisionJustification || "consignée")}</p></article>`;
      }
      const roleForms = catalog?.roles.filter((role) => role.status === "active").flatMap((role) => {
        const scopeDefinitions = catalog.scopeTypes.filter((scope) =>
          scope.status === "active" && role.scopeTypes.includes(scope.scope_type_id)
        );
        return scopeDefinitions.map((scope) => {
          const scopeField = scope.scope_type_id === "global"
            ? '<input type="hidden" name="scope_id" value="">'
            : `<label>Identifiant du périmètre<input name="scope_id" maxlength="191" required placeholder="${escapeHtml(scope.displayName)}"></label>`;
          return `<form class="grant" method="post" action="/admin/access-requests/${escapeHtml(line.lineId)}/approve"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="catalog_version" value="${escapeHtml(catalog.catalogVersion)}"><input type="hidden" name="role_id" value="${escapeHtml(role.role_id)}"><input type="hidden" name="scope_type" value="${escapeHtml(scope.scope_type_id)}"><label>Identité NSK cible<select name="identity_id" required><option value="">Sélectionner…</option>${activeIdentityOptions}</select></label>${scopeField}<label>Justification de l’octroi<input name="justification" minlength="20" maxlength="500" required placeholder="Pourquoi cet accès est-il légitime ?"></label><button type="submit">Approuver comme ${escapeHtml(role.displayName)}</button></form>`;
        });
      }) ?? [];
      const approval = roleForms.length
        ? roleForms.join("")
        : '<div class="facts"><p><strong>Catalogue indisponible :</strong> cette ligne ne peut pas être approuvée tant que l’application n’a pas publié ses rôles.</p></div>';
      const refusal = `<form class="grant" method="post" action="/admin/access-requests/${escapeHtml(line.lineId)}/refuse"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><label>Motif du refus<input name="justification" minlength="20" maxlength="500" required placeholder="Pourquoi cette demande est-elle refusée ?"></label><button class="secondary" type="submit">Refuser cette application</button></form>`;
      return `<article class="entry"><h3>${escapeHtml(line.applicationName)}</h3><p><span class="pill">En attente</span></p><div class="actions">${approval}${refusal}</div></article>`;
    }).join("");
    return `<section class="request"><h2>${escapeHtml(accessRequest.applicantName)}</h2><p><strong>Adresse :</strong> ${escapeHtml(accessRequest.applicantEmail)}<br><strong>Demandée le :</strong> ${escapeHtml(formatDate(accessRequest.requestedAt))}<br><strong>Motif :</strong> ${escapeHtml(accessRequest.reason)}<br><span class="note">Référence : ${escapeHtml(accessRequest.requestId)}</span></p><div class="directory">${lines}</div></section>`;
  }).join("");
  return `<h1>Demandes d’accès</h1><p>Chaque application est décidée séparément. Une approbation crée ou réactive exactement le rôle publié choisi ; aucun compte ni privilège n’est déduit de l’adresse électronique.</p>${requestCards || '<div class="facts"><p>Aucune demande en attente.</p></div>'}<nav><a class="button secondary" href="/admin/access-decisions">Accès applicatifs</a><a class="button secondary" href="/">Retour à l’accueil</a><form method="post" action="/auth/logout"><button class="secondary" type="submit">Fermer la session</button></form></nav>`;
}

function renderNotifications(notifications, unreadCount, csrf) {
  const cards = notifications.map((notification) => {
    const unread = !notification.readAt;
    const readAction = unread
      ? `<form method="post" action="/notifications/${escapeHtml(notification.notificationId)}/read"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button class="secondary" type="submit">Marquer comme lue</button></form>`
      : '<span class="pill">Lue</span>';
    const sourceApplicationName = applicationDisplayName(
      notification.sourceApplicationId,
      notification.sourceApplicationName,
    );
    return `<article class="entry notification${unread ? " unread" : ""}"><p><span class="pill${unread ? "" : " inactive"}">${unread ? "Non lue" : "Lue"}</span> · ${escapeHtml(sourceApplicationName)}</p><h3>${escapeHtml(notification.title)}</h3><p>${escapeHtml(notification.message)}</p><p class="muted">${escapeHtml(formatDate(notification.occurredAt))} · ${escapeHtml(notification.contextResourceType)} <code>${escapeHtml(notification.contextResourceId)}</code></p>${readAction}</article>`;
  }).join("");
  const allRead = unreadCount > 0
    ? `<form method="post" action="/notifications/read-all"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button class="secondary" type="submit">Tout marquer comme lu</button></form>` : "";
  const headingLayout = `<style>.notification-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:24px}.notification-heading>div{min-width:0}.notification-heading h1{margin-bottom:12px}.notification-heading p{margin-bottom:0}.notification-heading form{flex:0 0 auto;margin-top:22px}@media(max-width:700px){.notification-heading{display:block}.notification-heading form{margin-top:18px}.notification-heading button{width:100%}}</style>`;
  return `${headingLayout}<div class="notification-heading"><div><h1>Centre de notifications</h1><p>Ce centre interne est le canal de référence. Lire une notification ne la supprime pas et aucun canal externe n’est activé par cette page.</p></div>${allRead}</div><div class="summary"><div class="metric"><strong>${escapeHtml(unreadCount)}</strong>non lue${unreadCount > 1 ? "s" : ""}</div><div class="metric"><strong>${escapeHtml(notifications.length)}</strong>affichée${notifications.length > 1 ? "s" : ""}</div></div><div class="directory">${cards || '<div class="facts"><p>Aucune notification pour le moment.</p></div>'}</div>`;
}

function renderPersonalSessions(sessions, csrf, actionToken, { returnTo, theme }) {
  const accountQuery = `?return_to=${encodeURIComponent(returnTo)}&theme=${encodeURIComponent(theme)}`;
  const returnLabel = new URL(returnTo).origin === "https://nsktech.fr" ? "Retour aux applications" : "Retour à l’application";
  const activeOthers = sessions.filter((session) => session.state === "active" && !session.current).length;
  const stateLabel = (session) => session.current ? "Session actuelle"
    : session.state === "active" ? "Active"
      : session.state === "expired" ? "Expirée" : "Fermée";
  const cards = sessions.map((session) => {
    const action = session.state === "active" && !session.current
      ? `<form method="post" action="/account/sessions/revoke${accountQuery}"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="target" value="${escapeHtml(actionToken(session))}"><button class="secondary" type="submit">Fermer cette session</button></form>`
      : session.current
        ? '<p class="muted">Utilise « Fermer la session » pour quitter cet appareil.</p>' : "";
    return `<article class="entry"><p><span class="pill${session.state === "active" ? "" : " inactive"}">${escapeHtml(stateLabel(session))}</span></p><h3>${escapeHtml(session.applicationName)}</h3><p>${escapeHtml(session.contextLabel || "Connexion à l’application")}</p><p class="muted">Ouverte le ${escapeHtml(formatDate(session.issuedAt))}<br>Dernière activité ${escapeHtml(formatDate(session.lastSeenAt))}<br>Échéance au plus tard ${escapeHtml(formatDate(session.absoluteExpiresAt))}</p>${action}</article>`;
  }).join("");
  const closeOthers = activeOthers
    ? `<form method="post" action="/account/sessions/revoke-others${accountQuery}"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button class="secondary" type="submit">Fermer toutes les autres sessions (${escapeHtml(activeOthers)})</button></form>` : "";
  return `<h1>Mes sessions</h1><p>Retrouve ici les connexions ouvertes dans l’écosystème NSK Tech 09. Une fermeture distante prend effet au prochain contrôle serveur de l’application.</p><div class="facts"><p><strong>Protection :</strong> cette page n’affiche aucun cookie, secret, adresse réseau ni identifiant technique de session.</p></div><nav><a class="button" href="${escapeHtml(returnTo)}">${returnLabel}</a>${closeOthers}<a class="button secondary" href="/account${accountQuery}">Mon compte</a><form method="post" action="/auth/logout"><button class="secondary" type="submit">Fermer la session actuelle</button></form></nav><div class="directory">${cards || '<div class="facts"><p>Aucune session enregistrée.</p></div>'}</div>`;
}

function renderPersonalAccount({
  identity, applications, assignments, sessions, sessionsAvailable,
  providerKey, emailLoginEnabled, returnTo, theme,
}) {
  const query = `?return_to=${encodeURIComponent(returnTo)}&theme=${encodeURIComponent(theme)}`;
  const applicationById = new Map(applications.map((application) => [application.applicationId, application]));
  const applicationLabel = (applicationId) => applicationDisplayName(
    applicationId,
    applicationById.get(applicationId)?.displayName,
  );
  const roleLabels = {
    administrator: "Administrateur", admin: "Administrateur", owner: "Propriétaire",
    reader: "Lecteur", user: "Utilisateur", "energy-owner": "Propriétaire Énergie",
    "portal-user": "Utilisateur du portail", "tasks-administrator": "Administrateur des tâches",
    "tasks-pilot-reader": "Lecteur du pilote", "tasks-writer": "Contributeur aux tâches",
  };
  const activeAssignments = assignments.filter((assignment) =>
    assignment.subjectId === identity.identityId && assignment.status === "active"
  );
  const scopeLabel = (assignment) => {
    if (!assignment.scopeType || assignment.scopeType === "global") return "Tous les périmètres";
    const type = assignment.scopeType === "site" ? "Site" : assignment.scopeType;
    return assignment.scopeId ? `${type} : ${assignment.scopeId}` : `${type} attribué`;
  };
  const assignmentsByApplication = new Map();
  for (const assignment of activeAssignments) {
    const grouped = assignmentsByApplication.get(assignment.applicationId) ?? [];
    grouped.push(assignment);
    assignmentsByApplication.set(assignment.applicationId, grouped);
  }
  const accessCards = [...assignmentsByApplication.entries()]
    .sort(([leftId], [rightId]) => {
      const left = applicationLabel(leftId);
      const right = applicationLabel(rightId);
      return left.localeCompare(right, "fr");
    })
    .map(([applicationId, groupedAssignments]) => {
      const rows = groupedAssignments
        .sort((left, right) => (roleLabels[left.roleId] || left.roleId)
          .localeCompare(roleLabels[right.roleId] || right.roleId, "fr"))
        .map((assignment) => `<li class="access-role"><strong>${escapeHtml(roleLabels[assignment.roleId] || assignment.roleId)}</strong><span>${escapeHtml(scopeLabel(assignment))}</span></li>`)
        .join("");
      const count = groupedAssignments.length;
      return `<article class="entry assignment access-application"><div class="access-application-heading"><h3>${escapeHtml(applicationLabel(applicationId))}</h3><span class="pill">${escapeHtml(count)} rôle${count > 1 ? "s" : ""} actif${count > 1 ? "s" : ""}</span></div><ul class="access-role-list">${rows}</ul><p class="note">Affichage en lecture seule. Les modifications nécessitent une décision habilitée dans Administration.</p></article>`;
    }).join("");
  const providerName = providerKey === EMAIL_LOGIN_PROVIDER ? "Courriel"
    : providerKey === "infomaniak" ? "Infomaniak"
      : providerKey === "nsktech" ? "Session NSK Tech 09" : providerKey;
  const sessionActivity = sessions.slice(0, 3).map((item) =>
    `<li><strong>${escapeHtml(item.applicationName)}</strong> · dernière activité ${escapeHtml(formatDate(item.lastSeenAt))}${item.current ? " · session actuelle" : ""}</li>`
  ).join("");
  const sessionNavigation = sessionsAvailable
    ? `<a class="button secondary" href="/account/sessions${query}">Gérer mes sessions</a>` : "";
  const sessionSection = sessionsAvailable
    ? `<p><strong>${escapeHtml(sessions.filter((item) => item.state === "active").length)}</strong> session(s) active(s)</p><ul class="permissions">${sessionActivity || "<li>Aucune activité récente enregistrée.</li>"}</ul><a class="button secondary" href="/account/sessions${query}">Voir et fermer mes sessions</a>`
    : '<p><span class="pill inactive">Fonction temporairement indisponible</span></p><p>Ton profil et tes droits restent consultables. La gestion centralisée des sessions n’est pas activée pour cette connexion.</p>';
  return `<h1>Mon compte NSK Tech 09</h1><p>Ton espace personnel central réunit ton identité, tes accès et la sécurité de tes connexions. Il est distinct de la console d’administration.</p><nav><a class="button" href="${escapeHtml(returnTo)}">Retour à l’application</a>${sessionNavigation}</nav><div class="directory account-sections"><section class="entry assignment"><p><span class="pill">Identité ${escapeHtml(identity.status)}</span></p><h2>Profil et coordonnées</h2><p><strong>${escapeHtml(identity.displayName)}</strong><br><a href="mailto:${escapeHtml(identity.email)}">${escapeHtml(identity.email)}</a></p><p class="note">L’adresse affichée est l’adresse de référence de ton identité NSK Tech 09. Sa modification exige une vérification centrale.</p></section><section class="entry"><h2>Méthodes de connexion</h2><p><strong>Méthode de cette session :</strong> ${escapeHtml(providerName || "centrale")}</p><p>Infomaniak : <span class="pill">Disponible</span><br>Courriel sans mot de passe : <span class="pill${emailLoginEnabled ? "" : " inactive"}">${emailLoginEnabled ? "Disponible" : "Non configuré"}</span></p><p class="note">Aucun mot de passe NSK n’est stocké par les applications. Les méthodes reconnues conduisent à la même identité centrale.</p></section><section class="entry"><h2>Sessions et activité récente</h2>${sessionSection}</section><section class="entry"><h2>Données personnelles</h2><p>Les données affichées servent à l’identification, à l’attribution des accès et à la traçabilité de sécurité.</p><p><a href="https://nsktech.fr/#confidentialite" target="_blank" rel="noopener noreferrer">Consulter la politique de confidentialité</a></p><p class="note">Les demandes de rectification ou d’exercice de droits sont instruites sans suppression de la traçabilité légitime.</p></section></div><h2>Applications, rôles et périmètres</h2><p>Cette vue est informative : elle ne permet ni de s’accorder un rôle ni d’élargir un périmètre.</p><div class="directory">${accessCards || '<div class="facts"><p>Aucun accès applicatif actif n’est attribué à cette identité.</p></div>'}</div>`;
}

function renderResponsibleAuthority(snapshot) {
  if (!snapshot) {
    return '<div class="facts"><p><span class="pill inactive">Supervision indisponible</span></p><p>Les pouvoirs administratifs ne peuvent pas être vérifiés pour le moment.</p></div>';
  }
  const status = snapshot.complete
    ? `<span class="pill">Autorité complète · ${escapeHtml(snapshot.grantedCount)}/${escapeHtml(snapshot.totalCount)}</span>`
    : `<span class="pill inactive">Autorité à compléter · ${escapeHtml(snapshot.grantedCount)}/${escapeHtml(snapshot.totalCount)}</span>`;
  const cards = snapshot.powers.map((power) => `<article class="entry${power.allowed ? " assignment" : ""}"><p><span class="pill${power.allowed ? "" : " inactive"}">${power.allowed ? "Pouvoir accordé" : "Pouvoir manquant"}</span></p><h3>${escapeHtml(power.label)}</h3><p>${escapeHtml(power.description)}</p>${power.allowed ? `<a class="button secondary" href="${escapeHtml(power.href)}">Ouvrir</a>` : '<p class="note">Une habilitation explicite et auditée est nécessaire.</p>'}</article>`).join("");
  const title = snapshot.legalOwner ? "Responsable légal et opérationnel" : "Autorité administrative";
  return `<div class="facts"><p><strong>${title} :</strong> ${status}</p><p>${snapshot.complete ? "Tous les pouvoirs de gouvernance sont disponibles, chacun restant séparé, contrôlé et audité." : "Aucun passe-droit global n’est utilisé : les pouvoirs manquants doivent être accordés séparément."}</p></div><h2>Supervision générale</h2><div class="directory">${cards}</div>`;
}

function renderOperatorSessions(sessions, csrf, actionToken) {
  const cards = sessions.map((session) => {
    const action = session.current
      ? '<p class="muted">La session opérateur courante se ferme uniquement depuis l’espace personnel.</p>'
      : `<form class="grant" method="post" action="/admin/sessions/revoke"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="target" value="${escapeHtml(actionToken(session))}"><label>Justification de la fermeture<input name="justification" minlength="20" maxlength="500" required placeholder="Pourquoi cette session doit-elle être fermée ?"></label><button class="secondary" type="submit">Révoquer cette session</button></form>`;
    const identityState = session.identityStatus === "active" ? "Identité active" : `Identité ${session.identityStatus}`;
    return `<article class="entry"><p><span class="pill">Session active</span> · ${escapeHtml(identityState)}</p><h3>${escapeHtml(session.identityName)}</h3><p>${escapeHtml(session.identityEmail)}<br><strong>${escapeHtml(session.applicationName)}</strong> · ${escapeHtml(session.contextLabel || "Connexion à l’application")}</p><p class="muted">Ouverte le ${escapeHtml(formatDate(session.issuedAt))}<br>Dernière activité ${escapeHtml(formatDate(session.lastSeenAt))}<br>Expiration d’inactivité ${escapeHtml(formatDate(session.idleExpiresAt))}<br>Échéance absolue ${escapeHtml(formatDate(session.absoluteExpiresAt))}</p>${action}</article>`;
  }).join("");
  return `<h1>Sessions actives de l’écosystème</h1><p>Cette console permet uniquement la révocation motivée d’une session active. Elle ne révèle ni cookie, ni secret, ni adresse réseau, ni identifiant technique.</p><div class="summary"><div class="metric"><strong>${escapeHtml(sessions.length)}</strong>session${sessions.length > 1 ? "s" : ""} active${sessions.length > 1 ? "s" : ""}</div></div><div class="facts"><p><strong>Périmètre :</strong> administration globale explicitement attribuée par la permission dédiée <code>administration:sessions:revoke</code>.</p><p><strong>Garde-fou :</strong> la session opérateur courante ne peut pas être fermée depuis cette console.</p></div><div class="directory">${cards || '<div class="facts"><p>Aucune session active enregistrée.</p></div>'}</div><nav><a class="button secondary" href="/">Retour à l’accueil</a><a class="button secondary" href="/account/sessions">Mes sessions</a></nav>`;
}

function renderIdentityStateAdministration(identities, csrf, actionToken) {
  const cards = identities.map((identity) => {
    const sessions = `${identity.activeSessionCount} session${identity.activeSessionCount > 1 ? "s" : ""} active${identity.activeSessionCount > 1 ? "s" : ""}`;
    const actions = [];
    if (identity.current) {
      actions.push('<p class="muted">Ta propre identité ne peut pas être suspendue ni désactivée depuis cette console.</p>');
    } else {
      if (identity.canSuspend) actions.push(`<form class="grant" method="post" action="/admin/identities/suspend"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="target" value="${escapeHtml(actionToken(identity))}"><label>Justification de la suspension<input name="justification" minlength="20" maxlength="500" required placeholder="Pourquoi cette identité doit-elle être suspendue ?"></label><button class="secondary" type="submit">Suspendre l’identité et fermer ses sessions</button></form>`);
      if (identity.canReactivate) actions.push(`<form class="grant" method="post" action="/admin/identities/reactivate"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="target" value="${escapeHtml(actionToken(identity))}"><label>Justification de la réactivation<input name="justification" minlength="20" maxlength="500" required placeholder="Pourquoi cette identité peut-elle être réactivée ?"></label><button type="submit">Réactiver sans restaurer les anciennes sessions</button></form>`);
      if (identity.canDisable) actions.push(`<form class="grant" method="post" action="/admin/identities/disable"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="target" value="${escapeHtml(actionToken(identity))}"><label>Justification de la désactivation<input name="justification" minlength="20" maxlength="500" required placeholder="Pourquoi cette identité doit-elle quitter l’écosystème ?"></label><button class="secondary" type="submit">Désactiver et révoquer tous les accès</button></form>`);
    }
    if (!actions.length) actions.push('<p class="muted">Aucune action autorisée pour cette identité.</p>');
    const labels = { active: "Identité active", suspended: "Identité suspendue", disabled: "Identité désactivée" };
    return `<article class="entry"><p><span class="pill${identity.status === "active" ? "" : " inactive"}">${labels[identity.status] || "Identité indisponible"}</span> · ${escapeHtml(sessions)}</p><h3>${escapeHtml(identity.displayName)}</h3><p>${escapeHtml(identity.email)}</p>${actions.join("")}</article>`;
  }).join("");
  return `<h1>Cycle de vie des identités</h1><p>Cette console suspend temporairement, réactive sans restaurer de connexion ou désactive une identité en révoquant définitivement ses sessions et affectations actives. Elle ne supprime ni la personne ni son histoire.</p><div class="facts"><p><strong>Refus par défaut :</strong> les permissions distinctes <code>administration:identities:suspend</code>, <code>administration:identities:reactivate</code> et <code>administration:identities:disable</code> ouvrent uniquement leur action respective.</p><p><strong>Atomicité :</strong> si l’état, une session ou une affectation change pendant la décision, aucune transition partielle n’est conservée.</p><p><strong>Non-résurrection :</strong> une réactivation ne restaure aucune session ; une désactivation révoque aussi les affectations et n’est pas réversible depuis cette console.</p></div><div class="directory">${cards || '<div class="facts"><p>Aucune identité active, suspendue ou désactivée enregistrée.</p></div>'}</div><nav><a class="button secondary" href="/">Retour à l’accueil</a><a class="button secondary" href="/admin/sessions">Sessions actives</a></nav>`;
}

function renderNotificationOperations(snapshot) {
  const actionable = snapshot.events.pending + snapshot.events.processing + snapshot.events.retrying;
  const processor = snapshot.processor || { status: "never_run" };
  const processorState = processor.status === "succeeded"
    ? '<span class="pill">Dernier cycle réussi</span>'
    : processor.status === "failed"
      ? '<span class="pill inactive">Dernier cycle en échec</span>'
      : '<span class="pill inactive">Aucun cycle consigné</span>';
  const processorDetails = processor.status === "never_run"
    ? "Le consommateur autonome n’a encore produit aucun état durable."
    : `Terminé le ${escapeHtml(formatDate(processor.lastFinishedAt))} · pris ${escapeHtml(processor.claimed)} · traités ${escapeHtml(processor.processed)} · repris ${escapeHtml(processor.retried)} · quarantaines ${escapeHtml(processor.quarantined)}${processor.errorCode ? ` · code ${escapeHtml(processor.errorCode)}` : ""}`;
  const externalState = snapshot.externalDeliveries.nonBlocked === 0
    ? '<span class="pill">Tous bloqués</span>'
    : `<span class="pill inactive">${escapeHtml(snapshot.externalDeliveries.nonBlocked)} non bloquée${snapshot.externalDeliveries.nonBlocked > 1 ? "s" : ""}</span>`;
  const resolutionCards = snapshot.recentResolutions.map((resolution) => {
    const suppressed = resolution.suppressed || {};
    return `<article class="entry"><h3>${escapeHtml(resolution.sourceApplicationId)}</h3><p><strong>${escapeHtml(resolution.internalNotificationCount)}</strong> notification${resolution.internalNotificationCount > 1 ? "s" : ""} interne${resolution.internalNotificationCount > 1 ? "s" : ""} · <strong>${escapeHtml(resolution.blockedExternalDeliveryCount)}</strong> livraison${resolution.blockedExternalDeliveryCount > 1 ? "s" : ""} externe${resolution.blockedExternalDeliveryCount > 1 ? "s" : ""} bloquée${resolution.blockedExternalDeliveryCount > 1 ? "s" : ""}</p><p>Écartées : action propre ${escapeHtml(suppressed.own_action || 0)} · préférences ${escapeHtml(suppressed.preferences || 0)} · identité non liée ${escapeHtml(suppressed.unlinked_identity || 0)}</p><p class="muted">Politique : <code>${escapeHtml(resolution.policyVersion)}</code><br>Événement : <code>${escapeHtml(resolution.eventId)}</code><br>Résolu le ${escapeHtml(formatDate(resolution.resolvedAt))}</p></article>`;
  }).join("");
  return `<h1>Exploitation des notifications</h1><p>Vue centrale en lecture seule de la file et de ses résolutions. Cette page ne traite aucun événement, ne modifie aucune préférence et n’ouvre aucun canal externe.</p><div class="summary"><div class="metric"><strong>${escapeHtml(actionable)}</strong>à traiter ou en cours</div><div class="metric"><strong>${escapeHtml(snapshot.events.processed)}</strong>événements traités</div><div class="metric"><strong>${escapeHtml(snapshot.notifications.total)}</strong>notifications internes</div><div class="metric"><strong>${escapeHtml(snapshot.events.quarantined)}</strong>événements en quarantaine</div><div class="metric"><strong>${escapeHtml(snapshot.notifications.unread)}</strong>notifications non lues</div><div class="metric"><strong>${escapeHtml(snapshot.externalDeliveries.blocked)}</strong>livraisons externes bloquées</div></div><div class="facts"><p><strong>Consommateur interne :</strong> ${processorState}<br>${processorDetails}</p><p><strong>Canaux externes :</strong> ${externalState}<br><strong>Suppressions cumulées :</strong> action propre ${escapeHtml(snapshot.suppressions.ownAction)} · préférences ${escapeHtml(snapshot.suppressions.preferences)} · identité non liée ${escapeHtml(snapshot.suppressions.unlinkedIdentity)}</p><p class="muted">Dernier événement reçu : ${snapshot.events.lastReceivedAt ? escapeHtml(formatDate(snapshot.events.lastReceivedAt)) : "aucun"} · dernier traitement : ${snapshot.events.lastProcessedAt ? escapeHtml(formatDate(snapshot.events.lastProcessedAt)) : "aucun"}</p></div><h2>Résolutions récentes</h2><div class="directory">${resolutionCards || '<div class="facts"><p>Aucune résolution enregistrée.</p></div>'}</div><nav><a class="button secondary" href="/">Retour à l’accueil</a><a class="button secondary" href="/notifications">Centre personnel</a><form method="post" action="/auth/logout"><button class="secondary" type="submit">Fermer la session</button></form></nav>`;
}

export function createHttpHandler({
  repository,
  authenticate = async () => null,
  oidcConfig = null,
  fetchImpl = fetch,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  administrationSessionAuthority = null,
  sessionAuthority = null,
  personalSessionManagement = null,
  operatorSessionManagement = null,
  identityStateManagement = null,
  portalOrigins = [],
  emailLogin = null,
  release = { commit: "unknown", builtAt: null, environment: "unknown" },
}) {
  if (!repository) throw new Error("repository is required");
  if (typeof authenticate !== "function") throw new Error("authenticate must be a function");
  const publicRequestAttempts = new Map();
  const emailLoginAttempts = new Map();

  function allowEmailLoginRequest(request, email, now = Date.now()) {
    const forwarded = String(request.headers["x-forwarded-for"] ?? "").split(",")[0].trim();
    const remote = forwarded || request.socket?.remoteAddress || "unknown";
    const key = createHash("sha256").update(`${remote}\n${String(email).trim().toLowerCase()}`, "utf8").digest("hex");
    const windowStart = now - 60 * 60 * 1000;
    const attempts = (emailLoginAttempts.get(key) ?? []).filter((timestamp) => timestamp > windowStart);
    if (attempts.length >= 3) return false;
    attempts.push(now);
    emailLoginAttempts.set(key, attempts);
    if (emailLoginAttempts.size > 5000) {
      for (const [candidate, values] of emailLoginAttempts) {
        if (!values.some((timestamp) => timestamp > windowStart)) emailLoginAttempts.delete(candidate);
      }
    }
    return true;
  }

  function allowPublicAccessRequest(request, email, now = Date.now()) {
    const forwarded = String(request.headers["x-forwarded-for"] ?? "").split(",")[0].trim();
    const remote = forwarded || request.socket?.remoteAddress || "unknown";
    const key = createHash("sha256").update(`${remote}\n${String(email).trim().toLowerCase()}`, "utf8").digest("hex");
    const windowStart = now - 60 * 60 * 1000;
    const attempts = (publicRequestAttempts.get(key) ?? []).filter((timestamp) => timestamp > windowStart);
    if (attempts.length >= 5) return false;
    attempts.push(now);
    publicRequestAttempts.set(key, attempts);
    if (publicRequestAttempts.size > 5000) {
      for (const [candidate, values] of publicRequestAttempts) {
        if (!values.some((timestamp) => timestamp > windowStart)) publicRequestAttempts.delete(candidate);
      }
    }
    return true;
  }

  function observeSessionInBackground(session) {
    if (administrationSessionAuthority?.mode !== "observe" ||
        session?.status !== "authenticated" || !session.identityId) return;
    try {
      Promise.resolve(administrationSessionAuthority.observe({
        credential: session.centralSession ?? null,
        identityId: session.identityId,
      })).catch(() => {});
    } catch { /* observation must never influence current access */ }
  }

  async function openCurrentSession(request) {
    if (!oidcConfig) throw new Error("oidc_not_configured");
    const session = open(
      parseCookies(request.headers.cookie).get(OIDC_SESSION_COOKIE),
      oidcConfig.sessionSecret,
      "oidc-session",
    );
    if (session?.sessionVersion !== CURRENT_SESSION_VERSION) throw new Error("session_cookie_outdated");
    observeSessionInBackground(session);
    if (administrationSessionAuthority?.mode === "enforce" && session?.status === "authenticated") {
      const assessment = await administrationSessionAuthority.assess({
        credential: session.centralSession ?? null,
        identityId: session.identityId,
      });
      if (!assessment.allowed) throw new Error(assessment.reasonCode);
    }
    return session;
  }

  async function attachCentralSession(session) {
    if (!administrationSessionAuthority || session?.status !== "authenticated" || !session.identityId) return session;
    const credential = await administrationSessionAuthority.issue({ identityId: session.identityId });
    return credential ? { ...session, centralSession: credential } : session;
  }

  async function personalAccountContent(session, returnTo, theme) {
    if (session?.status !== "authenticated" || !session.identityId) {
      throw new Error("fresh_authentication_required");
    }
    const [identity, applications, assignments] = await Promise.all([
      repository.getIdentity(session.identityId),
      repository.listApplications(),
      repository.listAllAssignments(),
    ]);
    let sessions = [];
    let sessionsAvailable = false;
    if (personalSessionManagement && session.centralSession?.sessionId) {
      try {
        sessions = await personalSessionManagement.listOwn({
          identityId: session.identityId,
          currentSessionId: session.centralSession.sessionId,
        });
        sessionsAvailable = true;
      } catch { /* account identity and rights remain available without session inventory */ }
    }
    if (!identity || identity.status !== "active") throw new Error("identity_not_active");
    const accountContent = renderPersonalAccount({
      identity, applications, assignments, sessions, sessionsAvailable,
      providerKey: session.providerKey ?? "infomaniak",
      emailLoginEnabled: emailLogin?.enabled === true,
      returnTo, theme,
    });
    const accountReturnLayout = `<style>#contenu{position:relative}#contenu>h1,#contenu>p:first-of-type{padding-right:230px}#contenu>nav:first-of-type>a:first-child{position:absolute;right:34px;top:76px;white-space:nowrap}#contenu>nav:first-of-type:not(:has(a:nth-of-type(2))){margin:0}.access-application-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.access-application-heading h3{margin-top:3px}.access-role-list{list-style:none;margin:18px 0;padding:0;display:grid;gap:10px}.access-role{display:grid;gap:3px;padding:12px;border-radius:9px;background:var(--muted-bg)}.access-role span{color:var(--muted);font-size:13px}@media(max-width:850px){#contenu>h1,#contenu>p:first-of-type{padding-right:0}#contenu>nav:first-of-type>a:first-child{position:static;white-space:normal}#contenu>nav:first-of-type:not(:has(a:nth-of-type(2))){margin-top:22px}}</style>`;
    return `${accountReturnLayout}${accountContent}`;
  }

  return async function handle(request, response) {
    setSecurityHeaders(response);
    const url = new URL(request.url, "https://n09.invalid");
    if (request.method === "GET" && STATIC_ASSETS.has(url.pathname)) {
      const asset = STATIC_ASSETS.get(url.pathname);
      response.statusCode = 200;
      response.setHeader("cache-control", asset.type.startsWith("text/javascript")
        ? "no-cache"
        : "public, max-age=86400");
      response.setHeader("content-type", asset.type);
      response.setHeader("x-content-type-options", "nosniff");
      response.end(asset.body);
      return;
    }
    if (url.pathname === "/health" && request.method === "GET") {
      writeJson(response, 200, { status: "ok", release });
      return;
    }
    if (url.pathname === "/auth/login" && request.method === "GET") {
      const localReturn = safeLoginReturnPath(url.searchParams.get("return_to")) ?? "/";
      const theme = safeAccountTheme(url.searchParams.get("theme"));
      let session = null;
      try { session = await openCurrentSession(request); } catch { /* show selector */ }
      if (session?.status === "authenticated") {
        redirect(response, localReturn);
        return;
      }
      writeHtml(response, 200, "Connexion", renderPortalLogin({
        returnTo: portalOrigins[0] ?? "https://nsktech.fr/", theme, localReturn,
        emailLoginEnabled: emailLogin?.enabled === true,
      }));
      return;
    }
    if (url.pathname === "/auth/email/request" && request.method === "POST") {
      const startedAt = Date.now();
      const waitForNeutralTiming = async () => {
        const remaining = 350 - (Date.now() - startedAt);
        if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
      };
      const acceptedPage = '<h1>Consulte ta messagerie</h1><p>Si cette adresse correspond à une identité NSK active, un lien de connexion vient d’être envoyé. Il expire dans dix minutes et ne fonctionne qu’une fois.</p><div class="facts"><p><strong>Confidentialité :</strong> cette réponse ne révèle jamais si une adresse est enregistrée.</p></div><a class="button secondary" href="/auth/login?return_to=%2F">Retour aux méthodes de connexion</a>';
      try {
        if (!emailLogin?.enabled || !oidcConfig) throw new EmailLoginError("email_login_unavailable", 503);
        const form = await readForm(request, maxBodyBytes);
        const email = String(form.get("email") ?? "");
        const returnTo = safeLoginReturnPath(String(form.get("return_to") ?? ""));
        if (!returnTo) throw new EmailLoginError("invalid_return_to");
        if (!allowEmailLoginRequest(request, email)) {
          writeHtml(response, 429, "Demande temporairement limitée", '<h1>Patiente quelques instants</h1><p>Le nombre de demandes est temporairement limité pour protéger ton compte.</p><a class="button" href="/auth/login?return_to=%2F">Retour</a>');
          return;
        }
        await requestEmailLogin({
          repository, email, returnTo, delivery: emailLogin.delivery,
          publicOrigin: emailLogin.publicOrigin,
        });
        await waitForNeutralTiming();
        writeHtml(response, 202, "Lien demandé", acceptedPage);
      } catch (error) {
        if (error instanceof EmailLoginError && error.code === "invalid_email") {
          writeHtml(response, 400, "Adresse invalide", '<h1>Adresse à vérifier</h1><p>Saisis une adresse de courriel valide.</p><a class="button" href="/auth/login?return_to=%2F">Retour</a>');
        } else {
          await waitForNeutralTiming();
          if (!(error instanceof EmailLoginError)) console.error(JSON.stringify({ event: "email_login_request_failed", reason: "delivery_or_repository_unavailable" }));
          writeHtml(response, error instanceof EmailLoginError ? error.status : 503, "Connexion momentanément indisponible", '<h1>Connexion momentanément indisponible</h1><p>Le lien ne peut pas être envoyé pour le moment. Aucun compte ni droit n’a été modifié.</p><a class="button" href="/auth/login?return_to=%2F">Réessayer</a>');
        }
      }
      return;
    }
    if (url.pathname === "/auth/email/confirm" && request.method === "GET") {
      const clearConfirmation = cookie(EMAIL_LOGIN_CONFIRMATION_COOKIE, "", { maxAge: 0, path: "/auth/email" });
      try {
        if (!emailLogin?.enabled || !oidcConfig) throw new EmailLoginError("email_login_unavailable", 503);
        const token = url.searchParams.get("token");
        if (token) {
          const inspected = await inspectEmailLogin({ repository, token });
          const expiresAt = new Date(inspected.expiresAt).valueOf();
          const confirmation = seal({ token, expiresAt }, oidcConfig.sessionSecret, "email-login-confirmation");
          response.statusCode = 303;
          response.setHeader("cache-control", "no-store");
          response.setHeader("location", "/auth/email/confirm");
          response.setHeader("set-cookie", cookie(EMAIL_LOGIN_CONFIRMATION_COOKIE, confirmation, {
            maxAge: Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000)), path: "/auth/email",
          }));
          response.end();
          return;
        }
        const confirmation = openEmailLoginConfirmation(
          parseCookies(request.headers.cookie).get(EMAIL_LOGIN_CONFIRMATION_COOKIE),
          oidcConfig.sessionSecret,
        );
        const inspected = await inspectEmailLogin({ repository, token: confirmation.token });
        const expiresAt = new Date(inspected.expiresAt).valueOf();
        writeHtml(response, 200, "Confirmer la connexion", '<h1>Confirmer la connexion</h1><p>Le lien est valide. Confirme pour ouvrir ta session NSK Tech 09.</p><form method="post" action="/auth/email/consume"><button type="submit">Me connecter</button></form><p class="note">Cette confirmation empêche les outils de sécurité de ta messagerie d’utiliser le lien à ta place.</p>', [
          cookie(EMAIL_LOGIN_CONFIRMATION_COOKIE, parseCookies(request.headers.cookie).get(EMAIL_LOGIN_CONFIRMATION_COOKIE), {
            maxAge: Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000)), path: "/auth/email",
          }),
        ]);
      } catch (error) {
        const unavailable = !(error instanceof EmailLoginError) || error.status === 503;
        if (!(error instanceof EmailLoginError)) console.error(JSON.stringify({ event: "email_login_confirmation_failed", reason: "repository_unavailable" }));
        writeHtml(response, unavailable ? 503 : 400, "Lien non validé", `<h1>${unavailable ? "Connexion momentanément indisponible" : "Lien invalide ou expiré"}</h1><p>${unavailable ? "Le registre central n’est pas disponible." : "Demande un nouveau lien de connexion. Aucun compte ni droit n’a été modifié."}</p><a class="button" href="/auth/login?return_to=%2F">Recommencer</a>`, [clearConfirmation]);
      }
      return;
    }
    if (url.pathname === "/auth/email/consume" && request.method === "POST") {
      const clearConfirmation = cookie(EMAIL_LOGIN_CONFIRMATION_COOKIE, "", { maxAge: 0, path: "/auth/email" });
      try {
        if (!emailLogin?.enabled || !oidcConfig) throw new EmailLoginError("email_login_unavailable", 503);
        const confirmation = openEmailLoginConfirmation(
          parseCookies(request.headers.cookie).get(EMAIL_LOGIN_CONFIRMATION_COOKIE),
          oidcConfig.sessionSecret,
        );
        const consumed = await consumeEmailLogin({ repository, token: confirmation.token });
        let session = {
          sessionVersion: CURRENT_SESSION_VERSION, providerKey: EMAIL_LOGIN_PROVIDER,
          issuer: EMAIL_LOGIN_ISSUER, subject: consumed.identity.identityId,
          identityId: consumed.identity.identityId, displayName: consumed.identity.displayName,
          status: "authenticated", csrf: randomUUID(), expiresAt: Date.now() + 8 * 60 * 60 * 1000,
        };
        session = await attachCentralSession(session);
        response.statusCode = 303;
        response.setHeader("cache-control", "no-store");
        response.setHeader("location", consumed.returnTo);
        response.setHeader("set-cookie", [
          clearConfirmation,
          cookie(OIDC_SESSION_COOKIE, seal(session, oidcConfig.sessionSecret, "oidc-session"), { maxAge: 8 * 60 * 60 }),
        ]);
        response.end();
      } catch (error) {
        const unavailable = !(error instanceof EmailLoginError) || error.status === 503;
        if (!(error instanceof EmailLoginError)) console.error(JSON.stringify({ event: "email_login_consumption_failed", reason: "repository_or_session_registry_unavailable" }));
        writeHtml(response, unavailable ? 503 : 400, "Lien non validé", `<h1>${unavailable ? "Connexion momentanément indisponible" : "Lien invalide ou expiré"}</h1><p>${unavailable ? "Le registre central n’est pas disponible." : "Demande un nouveau lien de connexion. Aucun compte ni droit n’a été modifié."}</p><a class="button" href="/auth/login?return_to=%2F">Recommencer</a>`, [clearConfirmation]);
      }
      return;
    }
    if (url.pathname === "/application-login/authorize" && request.method === "GET") {
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        const loginRequest = validateAuthorizationRequest(url.searchParams);
        let session;
        try { session = await openCurrentSession(request); } catch { /* login below */ }
        if (!session) {
          redirect(response, `/auth/login?return_to=${encodeURIComponent(`${url.pathname}${url.search}`)}`);
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
        const identity = await exchangeApplicationLoginCode({
          repository,
          principal,
          payload,
          sessionAuthority,
        });
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
    if (url.pathname === "/portal/login" && request.method === "GET") {
      const fallback = portalOrigins[0] ? `${portalOrigins[0]}/#applications` : null;
      const returnTo = safePortalReturn(url.searchParams.get("return_to"), portalOrigins, fallback);
      const theme = safeAccountTheme(url.searchParams.get("theme"));
      if (!oidcConfig || !returnTo || !sessionAuthority) {
        writeHtml(response, 503, "Portail indisponible", '<h1>Portail momentanément indisponible</h1><p>La chaîne de connexion centrale n’est pas entièrement configurée.</p><a class="button" href="/">Retour</a>');
        return;
      }
      let identitySession;
      try { identitySession = await openCurrentSession(request); } catch { /* authenticate below */ }
      if (!identitySession) {
        writeHtml(response, 200, "Connexion", renderPortalLogin({
          returnTo, theme, emailLoginEnabled: emailLogin?.enabled === true,
        }));
        return;
      }
      try {
        const portalSession = await issuePortalSession({
          repository, sessionAuthority, identitySession, sessionSecret: oidcConfig.sessionSecret,
        });
        response.statusCode = 303;
        response.setHeader("cache-control", "no-store");
        response.setHeader("location", returnTo);
        response.setHeader("set-cookie", cookie(PORTAL_SESSION_COOKIE, portalSession, { maxAge: 4 * 60 * 60, path: "/portal" }));
        response.end();
      } catch (error) {
        const denied = error?.message === "portal_access_denied";
        writeHtml(response, denied ? 403 : 503, "Connexion au portail refusée",
          `<h1>Connexion au portail refusée</h1><p>${denied ? "Cette identité ne possède pas l’accès central au portail." : "Le registre central n’est pas vérifiable pour le moment."} Aucun accès implicite n’a été ouvert.</p><a class="button" href="/">Retour</a>`);
      }
      return;
    }
    if (url.pathname === "/portal/session") {
      const requestOrigin = request.headers.origin;
      if (typeof requestOrigin !== "string" || !portalOrigins.includes(requestOrigin)) {
        writeJson(response, 403, { error: "origin_not_allowed" });
        return;
      }
      response.setHeader("access-control-allow-origin", requestOrigin);
      response.setHeader("access-control-allow-credentials", "true");
      response.setHeader("vary", "Origin");
      if (request.method === "OPTIONS") {
        response.statusCode = 204;
        response.setHeader("access-control-allow-methods", "GET, OPTIONS");
        response.end();
        return;
      }
      if (request.method !== "GET") {
        response.setHeader("allow", "GET, OPTIONS");
        writeJson(response, 405, { error: "method_not_allowed" });
        return;
      }
      try {
        if (!oidcConfig || !sessionAuthority) throw new Error("portal_not_configured");
        const portalSession = openPortalSession(
          parseCookies(request.headers.cookie).get(PORTAL_SESSION_COOKIE), oidcConfig.sessionSecret,
        );
        const directory = await portalDirectory({ repository, sessionAuthority, session: portalSession });
        writeJson(response, 200, {
          authenticated: true,
          user: { displayName: directory.identity.displayName, email: directory.identity.email },
          applications: directory.applications,
        });
      } catch {
        writeJson(response, 401, { authenticated: false, applications: [] });
      }
      return;
    }
    if (url.pathname === "/portal/access-requests") {
      const requestOrigin = request.headers.origin;
      if (typeof requestOrigin !== "string" || !portalOrigins.includes(requestOrigin)) {
        writeJson(response, 403, { error: "origin_not_allowed" });
        return;
      }
      response.setHeader("access-control-allow-origin", requestOrigin);
      response.setHeader("vary", "Origin");
      if (request.method === "OPTIONS") {
        response.statusCode = 204;
        response.setHeader("access-control-allow-methods", "POST, OPTIONS");
        response.setHeader("access-control-allow-headers", "content-type");
        response.end();
        return;
      }
      if (request.method !== "POST") {
        response.setHeader("allow", "POST, OPTIONS");
        writeJson(response, 405, { error: "method_not_allowed" });
        return;
      }
      let correlationId = randomUUID();
      try {
        const { payload } = await readJson(request, maxBodyBytes);
        if (!allowPublicAccessRequest(request, payload?.email)) {
          throw new AccessRequestError("rate_limited", 429);
        }
        const result = await submitPublicAccessRequest(repository, { ...payload, correlationId });
        writeJson(response, 202, {
          accepted: true, request_id: result.requestId, status: result.status,
        }, correlationId);
      } catch (error) {
        if (error instanceof HttpInputError || error instanceof AccessRequestError) {
          writeJson(response, error.status, { error: error.code }, correlationId);
        } else {
          writeJson(response, 503, { error: "access_request_service_unavailable" }, correlationId);
        }
      }
      return;
    }
    if (url.pathname === "/portal/logout" && request.method === "POST") {
      const fallback = portalOrigins[0] ? `${portalOrigins[0]}/` : null;
      const returnTo = safePortalReturn(url.searchParams.get("return_to"), portalOrigins, fallback);
      if (!returnTo || !trustedPortalLogoutRequest(request)) {
        writeJson(response, 403, { error: "origin_not_allowed" });
        return;
      }
      try {
        if (!oidcConfig || !sessionAuthority) throw new Error("portal_not_configured");
        const portalSession = openPortalSession(
          parseCookies(request.headers.cookie).get(PORTAL_SESSION_COOKIE), oidcConfig.sessionSecret,
        );
        await revokePortalSession({ sessionAuthority, session: portalSession });
        response.statusCode = 303;
        response.setHeader("cache-control", "no-store");
        response.setHeader("location", returnTo);
        response.setHeader("set-cookie", cookie(PORTAL_SESSION_COOKIE, "", { maxAge: 0, path: "/portal" }));
        response.end();
      } catch {
        writeHtml(response, 503, "Déconnexion en attente", '<h1>Déconnexion en attente</h1><p>La révocation centrale ne peut pas encore être confirmée. Aucun succès fictif n’est affiché.</p><a class="button" href="/">Réessayer</a>');
      }
      return;
    }
    if (url.pathname === "/portal/account" && request.method === "GET") {
      const fallback = portalOrigins[0] ? `${portalOrigins[0]}/#applications` : "https://nsktech.fr/#applications";
      const returnTo = safeAccountReturn(url.searchParams.get("return_to"), portalOrigins, fallback);
      const theme = safeAccountTheme(url.searchParams.get("theme"));
      const accountPath = `/account?return_to=${encodeURIComponent(returnTo)}&theme=${encodeURIComponent(theme)}`;
      let accountSessionCookie = null;
      try {
        let session;
        try {
          session = await openCurrentSession(request);
          if (!session.centralSession?.sessionId) {
            session = await attachCentralSession(session);
            if (!session.centralSession?.sessionId) throw new Error("account_session_not_enrolled");
            accountSessionCookie = cookie(
              OIDC_SESSION_COOKIE,
              seal(session, oidcConfig.sessionSecret, "oidc-session"),
              { maxAge: Math.max(1, Math.ceil((session.expiresAt - Date.now()) / 1000)) },
            );
          }
        } catch {
          if (!oidcConfig || !sessionAuthority || !administrationSessionAuthority) throw new Error("account_bridge_unavailable");
          const portalSession = openPortalSession(
            parseCookies(request.headers.cookie).get(PORTAL_SESSION_COOKIE), oidcConfig.sessionSecret,
          );
          const directory = await portalDirectory({ repository, sessionAuthority, session: portalSession });
          session = await attachCentralSession({
            sessionVersion: CURRENT_SESSION_VERSION,
            providerKey: portalSession.providerKey ?? "nsktech",
            issuer: "nsktech:portal-session",
            subject: portalSession.identityId,
            identityId: portalSession.identityId,
            displayName: directory.identity.displayName,
            status: "authenticated",
            csrf: randomUUID(),
            expiresAt: Math.min(portalSession.expiresAt, Date.now() + 8 * 60 * 60 * 1000),
          });
          if (!session.centralSession?.sessionId) throw new Error("account_session_not_enrolled");
          accountSessionCookie = cookie(
            OIDC_SESSION_COOKIE,
            seal(session, oidcConfig.sessionSecret, "oidc-session"),
            { maxAge: Math.max(1, Math.ceil((session.expiresAt - Date.now()) / 1000)) },
          );
        }
        const content = await personalAccountContent(session, returnTo, theme);
        writeHtml(response, 200, "Mon compte", content, accountSessionCookie ? [accountSessionCookie] : []);
      } catch {
        redirect(response, `/auth/login?return_to=${encodeURIComponent(accountPath)}&theme=${encodeURIComponent(theme)}`);
      }
      return;
    }
    if (url.pathname === "/" && request.method === "GET") {
      let session = null;
      if (oidcConfig) {
        try { session = await openCurrentSession(request); } catch { /* anonymous */ }
      }
      const requestReference = session?.requestId
        ? `<p>Demande enregistrée : <strong>${escapeHtml(session.requestId)}</strong></p>` : "";
      const administrationLinks = [];
      let responsibleAuthority;
      if (session?.status === "authenticated" && session.csrf) {
        administrationLinks.push('<a class="button" href="/account">Mon compte</a>');
        try {
          responsibleAuthority = await assessResponsibleAuthority(repository, session.identityId);
        } catch {
          responsibleAuthority = null;
        }
        try {
          const decision = await authorizeIdentityLinkAdministration(repository, session.identityId);
          if (decision.allowed) administrationLinks.push('<a class="button" href="/admin/link-requests">Administrer les rattachements</a>');
        } catch { /* no administrative affordance on repository failure */ }
        try {
          const decision = await authorizeAccessAdministration(repository, session.identityId);
          if (decision.allowed) administrationLinks.push('<a class="button" href="/admin/access">Consulter les utilisateurs et accès</a>');
        } catch { /* no administrative affordance on repository failure */ }
        try {
          const decision = await authorizeAccessDecisionAdministration(repository, session.identityId);
          if (decision.allowed) {
            administrationLinks.push('<a class="button" href="/admin/access-decisions">Décider les accès</a>');
            if (typeof repository.listAccessRequests === "function") {
              const pendingRequests = await repository.listAccessRequests("pending");
              administrationLinks.push(`<a class="button" href="/admin/access-requests">Demandes d’accès${pendingRequests.length ? ` (${escapeHtml(pendingRequests.length)})` : ""}</a>`);
            }
          }
        } catch { /* no administrative affordance on repository failure */ }
        try {
          const decision = await authorizeNotificationOperationsAdministration(repository, session.identityId);
          if (decision.allowed) administrationLinks.push('<a class="button" href="/admin/notification-operations">Exploiter les notifications</a>');
        } catch { /* no administrative affordance on repository failure */ }
        try {
          const decision = await authorizeSessionRevocationAdministration(repository, session.identityId);
          if (decision.allowed) administrationLinks.push('<a class="button" href="/admin/sessions">Gérer les sessions actives</a>');
        } catch { /* no administrative affordance on repository failure */ }
        try {
          const decision = await authorizeIdentityLifecycleAdministration(repository, session.identityId);
          if (decision.allowed) administrationLinks.push('<a class="button" href="/admin/identities">Gérer le cycle de vie des identités</a>');
        } catch { /* no administrative affordance on repository failure */ }
        if (typeof repository.countUnreadNotifications === "function") {
          try {
            const unread = await repository.countUnreadNotifications(session.identityId);
            administrationLinks.unshift(`<a class="button" href="/notifications">Notifications${unread ? ` (${escapeHtml(unread)})` : ""}</a>`);
          } catch { /* no notification affordance on repository failure */ }
        }
      }
      const authorityPanel = session?.status === "authenticated" &&
        (responsibleAuthority === null || responsibleAuthority?.legalOwner || responsibleAuthority?.grantedCount > 0)
        ? renderResponsibleAuthority(responsibleAuthority) : "";
      const authenticatedTitle = responsibleAuthority?.legalOwner
        ? "Poste de pilotage NSK Tech 09" : "Identité vérifiée";
      const content = session
        ? `<h1>${authenticatedTitle}</h1><p>Bienvenue <strong>${escapeHtml(responsibleAuthority?.identity?.displayName || session.displayName)}</strong>. La preuve d’identité est valide.</p><div class="facts"><p>État NSK : <strong>${session.status === "authenticated" ? "rattachée" : "rattachement requis"}</strong></p>${requestReference}<p>${session.status === "authenticated" ? "Le compte NSK est reconnu ; les droits restent contrôlés séparément." : "Aucun compte, rôle ou droit n’a été créé automatiquement. Une décision humaine reste obligatoire."}</p></div>${authorityPanel}<h2>Accès rapides</h2><nav>${administrationLinks.join("")}<form method="post" action="/auth/logout"><button class="secondary" type="submit">Fermer la session</button></form></nav>`
        : `<h1>Le cœur d’identité est prêt</h1><p>Choisis ta méthode pour présenter une preuve d’identité au registre central NSK.</p><div class="facts"><p><strong>Une identité centrale :</strong> la méthode de connexion ne change ni ton compte ni tes droits.</p><p><strong>Zéro privilège implicite :</strong> une identité inconnue reste sans droit.</p></div>${oidcConfig ? '<a class="button" href="/auth/login?return_to=%2F">Choisir une méthode de connexion</a>' : '<p>Le service d’identité n’est pas encore configuré.</p>'}`;
      writeHtml(response, 200, "Accueil", content);
      return;
    }
    const identityStateRoot = url.pathname === "/admin/identities";
    const identitySuspendRoute = url.pathname === "/admin/identities/suspend";
    const identityReactivateRoute = url.pathname === "/admin/identities/reactivate";
    const identityDisableRoute = url.pathname === "/admin/identities/disable";
    if (identityStateRoot || identitySuspendRoute || identityReactivateRoute || identityDisableRoute) {
      let session;
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        session = await openCurrentSession(request);
      } catch {
        writeHtml(response, 401, "Connexion requise", '<h1>Connexion requise</h1><p>Une session NSK valide est nécessaire pour administrer le cycle de vie des identités.</p><a class="button" href="/">Se connecter</a>');
        return;
      }
      if (session.status !== "authenticated" || !session.identityId || !session.csrf ||
          !session.centralSession?.sessionId) {
        writeHtml(response, 401, "Nouvelle connexion requise", '<h1>Nouvelle connexion requise</h1><p>Renouvelle ta session afin d’accéder à l’administration sécurisée.</p><a class="button" href="/">Retour</a>');
        return;
      }
      let access;
      try {
        access = await authorizeIdentityLifecycleAdministration(repository, session.identityId);
      } catch {
        writeHtml(response, 503, "Identités indisponibles", '<h1>Administration momentanément indisponible</h1><p>Les pouvoirs de cycle de vie ne peuvent pas être vérifiés. Aucune identité n’a été modifiée.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (!access.allowed) {
        writeHtml(response, 403, "Accès refusé", '<h1>Accès refusé</h1><p>Cette identité ne possède aucune permission dédiée au cycle de vie des identités. Aucun droit implicite n’est accordé.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (!identityStateManagement) {
        writeHtml(response, 503, "Identités indisponibles", '<h1>Identités momentanément indisponibles</h1><p>Aucune identité n’a été modifiée.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (identityStateRoot && request.method === "GET") {
        try {
          const identities = await identityStateManagement.listLifecycle({ operatorIdentityId: session.identityId });
          const actionToken = (target) => seal({
            operatorIdentityId: session.identityId,
            targetIdentityId: target.identityId,
            expectedStatus: target.status,
            expiresAt: Date.now() + 10 * 60_000,
          }, oidcConfig.sessionSecret, "identity-state-action");
          writeHtml(response, 200, "Cycle de vie des identités", renderIdentityStateAdministration(identities, session.csrf, actionToken));
        } catch {
          writeHtml(response, 503, "Identités indisponibles", '<h1>Identités momentanément indisponibles</h1><p>Le registre n’a pas pu être consulté. Aucune identité n’a été modifiée.</p><a class="button" href="/">Retour</a>');
        }
        return;
      }
      if ((identitySuspendRoute || identityReactivateRoute || identityDisableRoute) && request.method === "POST") {
        try {
          const form = await readForm(request, maxBodyBytes);
          if (!safeEqual(form.get("csrf"), session.csrf)) throw new HttpInputError(403, "invalid_csrf");
          let target;
          try { target = open(form.get("target"), oidcConfig.sessionSecret, "identity-state-action"); }
          catch { throw new HttpInputError(400, "invalid_identity_target"); }
          if (target.operatorIdentityId !== session.identityId || !validIdentityStateTarget(target)) {
            throw new HttpInputError(400, "invalid_identity_target");
          }
          const justification = String(form.get("justification") ?? "").trim();
          if (justification.length < 20 || justification.length > 500) {
            throw new HttpInputError(400, "invalid_justification");
          }
          const operation = identitySuspendRoute
            ? identityStateManagement.suspend
            : identityReactivateRoute ? identityStateManagement.reactivate : identityStateManagement.disable;
          await operation({
            operatorIdentityId: session.identityId,
            targetIdentityId: target.targetIdentityId,
            expectedStatus: target.expectedStatus,
            justification,
          });
          redirect(response, "/admin/identities");
        } catch (error) {
          const status = error instanceof HttpInputError || error instanceof IdentityStateError ? error.status : 503;
          writeHtml(response, status, "Identité non modifiée", '<h1>Identité non modifiée</h1><p>La demande est invalide, périmée, hors périmètre ou concurrente. Aucune transition partielle n’a été conservée et aucune ancienne session n’a été restaurée.</p><a class="button" href="/admin/identities">Retour</a>');
        }
        return;
      }
      response.setHeader("allow", identityStateRoot ? "GET" : "POST");
      writeJson(response, 405, { error: "method_not_allowed" });
      return;
    }
    const operatorSessionsRoot = url.pathname === "/admin/sessions";
    const operatorSessionRevoke = url.pathname === "/admin/sessions/revoke";
    if (operatorSessionsRoot || operatorSessionRevoke) {
      let session;
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        session = await openCurrentSession(request);
      } catch {
        writeHtml(response, 401, "Connexion requise", '<h1>Connexion requise</h1><p>Une session NSK valide est nécessaire pour administrer les sessions.</p><a class="button" href="/">Se connecter</a>');
        return;
      }
      if (session.status !== "authenticated" || !session.identityId || !session.csrf ||
          !session.centralSession?.sessionId) {
        writeHtml(response, 401, "Nouvelle connexion requise", '<h1>Nouvelle connexion requise</h1><p>Renouvelle ta session afin d’accéder à l’administration sécurisée.</p><a class="button" href="/">Retour</a>');
        return;
      }
      let access;
      try {
        access = await authorizeSessionRevocationAdministration(repository, session.identityId);
      } catch {
        console.error(JSON.stringify({ event: "operator_session_administration_unavailable", reason: "authorization_repository_failure" }));
        writeHtml(response, 503, "Sessions indisponibles", '<h1>Administration momentanément indisponible</h1><p>Le pouvoir de révocation ne peut pas être vérifié. Aucune session n’a été modifiée.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (!access.allowed) {
        writeHtml(response, 403, "Accès refusé", '<h1>Accès refusé</h1><p>Cette identité ne possède pas la permission dédiée à la révocation des sessions. Aucun droit implicite n’est accordé.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (!operatorSessionManagement) {
        writeHtml(response, 503, "Sessions indisponibles", '<h1>Sessions momentanément indisponibles</h1><p>Aucune session n’a été modifiée.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (operatorSessionsRoot && request.method === "GET") {
        try {
          const sessions = await operatorSessionManagement.listActive({
            operatorIdentityId: session.identityId,
            currentSessionId: session.centralSession.sessionId,
          });
          const actionToken = (target) => seal({
            operatorIdentityId: session.identityId,
            targetIdentityId: target.identityId,
            targetSessionId: target.sessionId,
            expectedVersion: target.version,
            expiresAt: Date.now() + 10 * 60_000,
          }, oidcConfig.sessionSecret, "operator-session-action");
          writeHtml(response, 200, "Sessions actives", renderOperatorSessions(sessions, session.csrf, actionToken));
        } catch {
          console.error(JSON.stringify({ event: "operator_session_administration_unavailable", reason: "listing_repository_failure" }));
          writeHtml(response, 503, "Sessions indisponibles", '<h1>Sessions momentanément indisponibles</h1><p>Le registre n’a pas pu être consulté. Aucune session n’a été modifiée.</p><a class="button" href="/">Retour</a>');
        }
        return;
      }
      if (operatorSessionRevoke && request.method === "POST") {
        try {
          const form = await readForm(request, maxBodyBytes);
          if (!safeEqual(form.get("csrf"), session.csrf)) throw new HttpInputError(403, "invalid_csrf");
          let target;
          try {
            target = open(form.get("target"), oidcConfig.sessionSecret, "operator-session-action");
          } catch { throw new HttpInputError(400, "invalid_session_target"); }
          if (target.operatorIdentityId !== session.identityId || !validOperatorTarget(target)) {
            throw new HttpInputError(400, "invalid_session_target");
          }
          const justification = String(form.get("justification") ?? "").trim();
          if (justification.length < 20 || justification.length > 500) {
            throw new HttpInputError(400, "invalid_justification");
          }
          await operatorSessionManagement.revokeOne({
            operatorIdentityId: session.identityId,
            currentSessionId: session.centralSession.sessionId,
            targetIdentityId: target.targetIdentityId,
            targetSessionId: target.targetSessionId,
            expectedVersion: target.expectedVersion,
            justification,
          });
          redirect(response, "/admin/sessions");
        } catch (error) {
          const status = error instanceof HttpInputError || error instanceof OperatorSessionError
            ? error.status : 503;
          if (status >= 500) console.error(JSON.stringify({ event: "operator_session_revocation_failed", reason: "repository_rejected_decision" }));
          writeHtml(response, status, "Session non modifiée", '<h1>Session non modifiée</h1><p>La demande est invalide, périmée, hors périmètre ou concurrente. Aucune fermeture partielle n’a été présentée comme réussie.</p><a class="button" href="/admin/sessions">Retour</a>');
        }
        return;
      }
      response.setHeader("allow", operatorSessionsRoot ? "GET" : "POST");
      writeJson(response, 405, { error: "method_not_allowed" });
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
            sessionVersion: CURRENT_SESSION_VERSION,
            providerKey: "infomaniak",
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
            sessionVersion: CURRENT_SESSION_VERSION,
            providerKey: "infomaniak",
            issuer: INFOMANIAK_ISSUER, subject: claims.sub, displayName,
            status: "link_required", requestId: linkRequest.requestId,
            requestExpiresAt: linkRequest.expiresAt,
            expiresAt: Date.now() + 8 * 60 * 60 * 1000,
          };
        }
        session = await attachCentralSession(session);
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
        const unavailable = reason === "administration_session_registry_unavailable";
        writeHtml(response, unavailable ? 503 : 400, "Connexion non validée", `<h1>Connexion non validée</h1><p>${unavailable ? "Le registre central de sessions n’est pas disponible. Aucune session locale autonome n’a été créée." : "La preuve d’identité n’a pas pu être vérifiée. Aucun compte et aucun droit n’ont été modifiés."}</p>${diagnostic}<a class="button" href="/">Retour</a>`, [clearTransaction]);
      }
      return;
    }
    if (url.pathname === "/auth/session" && request.method === "GET") {
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        const session = await openCurrentSession(request);
        writeJson(response, 200, {
          authenticated: true, provider: session.providerKey ?? "infomaniak", status: session.status,
          display_name: session.displayName, request_id: session.requestId ?? null,
        });
      } catch { writeJson(response, 401, { authenticated: false }); }
      return;
    }
    if (url.pathname === "/auth/logout" && request.method === "POST") {
      if (administrationSessionAuthority?.mode === "enforce") {
        try {
          if (!oidcConfig) throw new Error("oidc_not_configured");
          const session = open(
            parseCookies(request.headers.cookie).get(OIDC_SESSION_COOKIE),
            oidcConfig.sessionSecret,
            "oidc-session",
          );
          if (session?.sessionVersion === CURRENT_SESSION_VERSION && session.status === "authenticated") {
            const result = await administrationSessionAuthority.revokeCurrent({
              credential: session.centralSession ?? null,
              identityId: session.identityId,
            });
            if (!result.revoked) throw new Error(result.reasonCode);
          } else if (session?.sessionVersion === CURRENT_SESSION_VERSION && session.status !== "link_required") {
            throw new Error("invalid_session_status");
          }
        } catch {
          writeHtml(response, 503, "Déconnexion en attente", '<h1>Déconnexion en attente</h1><p>La fermeture centrale de cette session ne peut pas encore être confirmée. Aucun succès fictif n’est affiché et le cookie est conservé pour permettre une nouvelle tentative.</p><a class="button" href="/">Réessayer</a>');
          return;
        }
      }
      response.statusCode = 303;
      response.setHeader("cache-control", "no-store");
      response.setHeader("location", "/");
      response.setHeader("set-cookie", cookie(OIDC_SESSION_COOKIE, "", { maxAge: 0 }));
      response.end();
      return;
    }
    if (url.pathname === "/account" && request.method === "GET") {
      const accountFallback = portalOrigins[0] ? `${portalOrigins[0]}/#applications` : "https://nsktech.fr/#applications";
      const accountReturnTo = safeAccountReturn(url.searchParams.get("return_to"), portalOrigins, accountFallback);
      const accountTheme = safeAccountTheme(url.searchParams.get("theme"));
      const accountPath = `/account?return_to=${encodeURIComponent(accountReturnTo)}&theme=${encodeURIComponent(accountTheme)}`;
      let session;
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        session = await openCurrentSession(request);
      } catch {
        redirect(response, `/auth/login?return_to=${encodeURIComponent(accountPath)}&theme=${encodeURIComponent(accountTheme)}`);
        return;
      }
      try {
        writeHtml(response, 200, "Mon compte", await personalAccountContent(
          session, accountReturnTo, accountTheme,
        ));
      } catch {
        writeHtml(response, 503, "Compte indisponible", '<h1>Compte momentanément indisponible</h1><p>Ton identité et tes droits ne peuvent pas être affichés de façon fiable. Aucun changement n’a été effectué.</p><a class="button" href="/">Retour</a>');
      }
      return;
    }
    const personalSessionsRoot = url.pathname === "/account/sessions";
    const personalSessionRevoke = url.pathname === "/account/sessions/revoke";
    const personalSessionsRevokeOthers = url.pathname === "/account/sessions/revoke-others";
    if (personalSessionsRoot || personalSessionRevoke || personalSessionsRevokeOthers) {
      const accountFallback = portalOrigins[0] ? `${portalOrigins[0]}/#applications` : "https://nsktech.fr/#applications";
      const accountReturnTo = safeAccountReturn(url.searchParams.get("return_to"), portalOrigins, accountFallback);
      const accountTheme = safeAccountTheme(url.searchParams.get("theme"));
      const accountQuery = `?return_to=${encodeURIComponent(accountReturnTo)}&theme=${encodeURIComponent(accountTheme)}`;
      let session;
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        session = await openCurrentSession(request);
      } catch {
        writeHtml(response, 401, "Connexion requise", '<h1>Connexion requise</h1><p>Une session NSK valide est nécessaire pour gérer tes connexions.</p><a class="button" href="/">Se connecter</a>');
        return;
      }
      if (session.status !== "authenticated" || !session.identityId || !session.csrf ||
          !session.centralSession?.sessionId) {
        writeHtml(response, 401, "Nouvelle connexion requise", '<h1>Nouvelle connexion requise</h1><p>Renouvelle ta session afin de gérer tes connexions.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (!personalSessionManagement) {
        writeHtml(response, 503, "Sessions indisponibles", '<h1>Sessions momentanément indisponibles</h1><p>Aucune connexion n’a été modifiée.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (personalSessionsRoot && request.method === "GET") {
        try {
          const sessions = await personalSessionManagement.listOwn({
            identityId: session.identityId,
            currentSessionId: session.centralSession.sessionId,
          });
          const actionToken = (target) => seal({
            identityId: session.identityId,
            targetSessionId: target.sessionId,
            expectedVersion: target.version,
            expiresAt: Date.now() + 10 * 60_000,
          }, oidcConfig.sessionSecret, "personal-session-action");
          writeHtml(response, 200, "Mes sessions", renderPersonalSessions(
            sessions, session.csrf, actionToken, { returnTo: accountReturnTo, theme: accountTheme },
          ));
        } catch {
          writeHtml(response, 503, "Sessions indisponibles", '<h1>Sessions momentanément indisponibles</h1><p>Le registre n’a pas pu être consulté. Aucune connexion n’a été modifiée.</p><a class="button" href="/">Retour</a>');
        }
        return;
      }
      if ((personalSessionRevoke || personalSessionsRevokeOthers) && request.method === "POST") {
        try {
          const form = await readForm(request, maxBodyBytes);
          if (!safeEqual(form.get("csrf"), session.csrf)) throw new HttpInputError(403, "invalid_csrf");
          if (personalSessionRevoke) {
            let target;
            try {
              target = open(form.get("target"), oidcConfig.sessionSecret, "personal-session-action");
            } catch { throw new HttpInputError(400, "invalid_session_target"); }
            if (target.identityId !== session.identityId || !Number.isSafeInteger(target.expectedVersion)) {
              throw new HttpInputError(400, "invalid_session_target");
            }
            await personalSessionManagement.revokeOne({
              identityId: session.identityId,
              currentSessionId: session.centralSession.sessionId,
              targetSessionId: target.targetSessionId,
              expectedVersion: target.expectedVersion,
            });
          } else {
            await personalSessionManagement.revokeAllOthers({
              identityId: session.identityId,
              currentSessionId: session.centralSession.sessionId,
            });
          }
          redirect(response, `/account/sessions${accountQuery}`);
        } catch (error) {
          const status = error instanceof HttpInputError || error instanceof PersonalSessionError
            ? error.status : 503;
          writeHtml(response, status, "Session non modifiée", `<h1>Session non modifiée</h1><p>La demande est invalide, périmée ou concurrente. Aucune fermeture partielle n’a été présentée comme réussie.</p><a class="button" href="/account/sessions${accountQuery}">Retour</a>`);
        }
        return;
      }
      response.setHeader("allow", personalSessionsRoot ? "GET" : "POST");
      writeJson(response, 405, { error: "method_not_allowed" });
      return;
    }
    const notificationsRoot = url.pathname === "/notifications";
    const notificationsReadAll = url.pathname === "/notifications/read-all";
    const notificationRead = url.pathname.match(/^\/notifications\/([0-9a-f]{64})\/read$/i);
    if (notificationsRoot || notificationsReadAll || notificationRead) {
      let session;
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        session = await openCurrentSession(request);
      } catch {
        writeHtml(response, 401, "Connexion requise", '<h1>Connexion requise</h1><p>Une session NSK valide est nécessaire pour consulter tes notifications.</p><a class="button" href="/">Se connecter</a>');
        return;
      }
      if (session.status !== "authenticated" || !session.identityId || !session.csrf) {
        writeHtml(response, 401, "Nouvelle connexion requise", '<h1>Nouvelle connexion requise</h1><p>Renouvelle ta session afin d’accéder à tes notifications.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (notificationsRoot && request.method === "GET") {
        try {
          const [notifications, unreadCount] = await Promise.all([
            repository.listNotifications(session.identityId),
            repository.countUnreadNotifications(session.identityId),
          ]);
          writeHtml(response, 200, "Notifications", renderNotifications(notifications, unreadCount, session.csrf));
        } catch {
          writeHtml(response, 503, "Notifications indisponibles", '<h1>Notifications momentanément indisponibles</h1><p>Aucun état de lecture n’a été modifié.</p><a class="button" href="/">Retour</a>');
        }
        return;
      }
      if ((notificationsReadAll || notificationRead) && request.method === "POST") {
        try {
          const form = await readForm(request, maxBodyBytes);
          if (!safeEqual(form.get("csrf"), session.csrf)) throw new HttpInputError(403, "invalid_csrf");
          if (notificationsReadAll) {
            await repository.markAllNotificationsRead({ identityId: session.identityId, readAt: new Date() });
          } else {
            await repository.markNotificationRead({
              identityId: session.identityId, notificationId: notificationRead[1].toLowerCase(), readAt: new Date(),
            });
          }
          redirect(response, "/notifications");
        } catch (error) {
          const status = error instanceof HttpInputError ? error.status : 503;
          writeHtml(response, status, "Lecture non modifiée", '<h1>Lecture non modifiée</h1><p>Aucun état de notification n’a été changé.</p><a class="button" href="/notifications">Retour</a>');
        }
        return;
      }
      response.setHeader("allow", notificationsRoot ? "GET" : "POST");
      writeJson(response, 405, { error: "method_not_allowed" });
      return;
    }
    if (url.pathname === "/admin/notification-operations") {
      if (request.method !== "GET") {
        response.setHeader("allow", "GET");
        writeJson(response, 405, { error: "method_not_allowed" });
        return;
      }
      let session;
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        session = await openCurrentSession(request);
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
        access = await authorizeNotificationOperationsAdministration(repository, session.identityId);
      } catch {
        console.error(JSON.stringify({ event: "notification_operations_unavailable", reason: "authorization_repository_failure" }));
        writeHtml(response, 503, "Exploitation indisponible", '<h1>Exploitation momentanément indisponible</h1><p>Le droit de consultation ne peut pas être vérifié.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (!access.allowed) {
        writeHtml(response, 403, "Accès refusé", '<h1>Accès refusé</h1><p>Cette identité ne possède pas la permission dédiée à l’exploitation des notifications.</p><a class="button" href="/">Retour</a>');
        return;
      }
      try {
        const snapshot = await repository.getNotificationOperationsSnapshot();
        writeHtml(response, 200, "Exploitation des notifications", renderNotificationOperations(snapshot));
      } catch {
        console.error(JSON.stringify({ event: "notification_operations_unavailable", reason: "snapshot_repository_failure" }));
        writeHtml(response, 503, "Exploitation indisponible", '<h1>Exploitation momentanément indisponible</h1><p>La file de notifications n’a pas pu être consultée. Aucun état n’a été modifié.</p><a class="button" href="/">Retour</a>');
      }
      return;
    }
    const accessDecisionRoot = url.pathname === "/admin/access-decisions";
    const accessGrantRoute = url.pathname === "/admin/access-decisions/grant";
    const accessRevocationRoute = url.pathname.match(/^\/admin\/access-decisions\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/revoke$/i);
    if (accessDecisionRoot || accessGrantRoute || accessRevocationRoute) {
      let session;
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        session = await openCurrentSession(request);
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
        access = await authorizeAccessDecisionAdministration(repository, session.identityId);
      } catch {
        console.error(JSON.stringify({ event: "access_decision_administration_unavailable", reason: "authorization_repository_failure" }));
        writeHtml(response, 503, "Administration indisponible", '<h1>Administration momentanément indisponible</h1><p>Aucune décision d’accès ne peut être vérifiée ou appliquée pour le moment.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (!access.allowed) {
        writeHtml(response, 403, "Accès refusé", '<h1>Accès refusé</h1><p>Cette identité ne possède pas la permission dédiée aux décisions d’accès. Aucun droit implicite n’est accordé.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (accessDecisionRoot && request.method === "GET") {
        try {
          const [identities, applications, assignments, catalogs] = await Promise.all([
            repository.listIdentities(), repository.listApplications(), repository.listAllAssignments(),
            repository.listLatestApplicationAccessCatalogs(),
          ]);
          writeHtml(response, 200, "Décisions d’accès", renderAccessDecisionAdministration(
            identities, applications, assignments, catalogs, session.csrf,
          ));
        } catch {
          console.error(JSON.stringify({ event: "access_decision_administration_unavailable", reason: "listing_repository_failure" }));
          writeHtml(response, 503, "Administration indisponible", '<h1>Administration momentanément indisponible</h1><p>Le registre n’a pas pu être consulté. Aucun accès n’a été modifié.</p><a class="button" href="/">Retour</a>');
        }
        return;
      }
      if (accessGrantRoute && request.method === "POST") {
        try {
          const form = await readForm(request, maxBodyBytes);
          if (!safeEqual(form.get("csrf"), session.csrf)) throw new HttpInputError(403, "invalid_csrf");
          await grantAccessAssignment(repository, {
            identityId: String(form.get("identity_id") ?? "").toLowerCase(),
            applicationId: String(form.get("application_id") ?? ""),
            roleId: String(form.get("role_id") ?? ""),
            scopeType: String(form.get("scope_type") ?? ""),
            scopeId: form.has("scope_id") ? String(form.get("scope_id") ?? "").trim() : null,
            catalogVersion: Number(form.get("catalog_version")),
            operatorIdentityId: session.identityId,
            justification: String(form.get("justification") ?? "").trim(),
          });
          redirect(response, "/admin/access-decisions");
        } catch (error) {
          if (error instanceof HttpInputError) {
            writeHtml(response, error.status, "Octroi non appliqué", `<h1>Octroi non appliqué</h1><p>La demande est invalide. Aucun accès n’a été modifié.</p><p class="note">Code : ${escapeHtml(error.code)}</p><a class="button" href="/admin/access-decisions">Retour</a>`);
          } else {
            console.error(JSON.stringify({ event: "access_grant_failed", reason: "repository_rejected_decision" }));
            writeHtml(response, 409, "Octroi non appliqué", '<h1>Octroi non appliqué</h1><p>Le catalogue, le rôle, le périmètre ou l’identité ne permet pas cet octroi. Aucun changement partiel n’a été conservé.</p><a class="button" href="/admin/access-decisions">Retour</a>');
          }
        }
        return;
      }
      if (accessRevocationRoute && request.method === "POST") {
        try {
          const form = await readForm(request, maxBodyBytes);
          if (!safeEqual(form.get("csrf"), session.csrf)) throw new HttpInputError(403, "invalid_csrf");
          const expectedVersion = Number(form.get("expected_version"));
          const justification = String(form.get("justification") ?? "").trim();
          if (!Number.isInteger(expectedVersion) || expectedVersion < 1) throw new HttpInputError(400, "invalid_assignment_version");
          if (justification.length < 20 || justification.length > 500) throw new HttpInputError(400, "invalid_justification");
          await revokeAccessAssignment(repository, {
            assignmentId: accessRevocationRoute[1].toLowerCase(),
            expectedVersion,
            operatorIdentityId: session.identityId,
            justification,
          });
          redirect(response, "/admin/access-decisions");
        } catch (error) {
          if (error instanceof HttpInputError) {
            writeHtml(response, error.status, "Révocation non appliquée", `<h1>Révocation non appliquée</h1><p>La demande est invalide. Aucun accès n’a été modifié.</p><p class="note">Code : ${escapeHtml(error.code)}</p><a class="button" href="/admin/access-decisions">Retour</a>`);
          } else {
            console.error(JSON.stringify({ event: "access_revocation_failed", reason: "repository_rejected_decision" }));
            writeHtml(response, 409, "Révocation non appliquée", '<h1>Révocation non appliquée</h1><p>L’affectation a changé, n’est plus active ou son retrait relève d’une gouvernance dédiée. Aucun changement partiel n’a été conservé.</p><a class="button" href="/admin/access-decisions">Retour</a>');
          }
        }
        return;
      }
      response.setHeader("allow", accessDecisionRoot ? "GET" : "POST");
      writeJson(response, 405, { error: "method_not_allowed" });
      return;
    }
    const accessRequestRoute = url.pathname.match(/^\/admin\/access-requests(?:\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/(approve|refuse))?$/i);
    if (accessRequestRoute) {
      let session;
      try {
        if (!oidcConfig) throw new Error("oidc_not_configured");
        session = await openCurrentSession(request);
      } catch {
        writeHtml(response, 401, "Connexion requise", '<h1>Connexion requise</h1><p>Une session NSK valide est nécessaire pour traiter les demandes d’accès.</p><a class="button" href="/">Se connecter</a>');
        return;
      }
      if (session.status !== "authenticated" || !session.identityId || !session.csrf) {
        writeHtml(response, 401, "Nouvelle connexion requise", '<h1>Nouvelle connexion requise</h1><p>Renouvelle ta session afin d’accéder à l’administration sécurisée.</p><a class="button" href="/">Retour</a>');
        return;
      }
      let access;
      try { access = await authorizeAccessDecisionAdministration(repository, session.identityId); }
      catch { access = { allowed: false, unavailable: true }; }
      if (access.unavailable) {
        writeHtml(response, 503, "Demandes indisponibles", '<h1>Demandes momentanément indisponibles</h1><p>Les pouvoirs ne peuvent pas être vérifiés. Aucune décision n’a été appliquée.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (!access.allowed) {
        writeHtml(response, 403, "Accès refusé", '<h1>Accès refusé</h1><p>Cette identité ne possède pas la permission de décider les accès.</p><a class="button" href="/">Retour</a>');
        return;
      }
      if (!accessRequestRoute[1] && request.method === "GET") {
        try {
          const [requests, identities, catalogs] = await Promise.all([
            repository.listAccessRequests("pending"), repository.listIdentities("active"),
            repository.listLatestApplicationAccessCatalogs(),
          ]);
          writeHtml(response, 200, "Demandes d’accès", renderAccessRequestAdministration(
            requests, identities, catalogs, session.csrf,
          ));
        } catch {
          writeHtml(response, 503, "Demandes indisponibles", '<h1>Demandes momentanément indisponibles</h1><p>Le registre n’a pas pu être consulté. Aucune décision n’a été appliquée.</p><a class="button" href="/">Retour</a>');
        }
        return;
      }
      if (accessRequestRoute[1] && request.method === "POST") {
        try {
          const form = await readForm(request, maxBodyBytes);
          if (!safeEqual(form.get("csrf"), session.csrf)) throw new HttpInputError(403, "invalid_csrf");
          const input = {
            lineId: accessRequestRoute[1].toLowerCase(),
            operatorIdentityId: session.identityId,
            justification: String(form.get("justification") ?? "").trim(),
          };
          if (accessRequestRoute[2] === "approve") {
            await approveAccessRequestLine(repository, {
              ...input,
              identityId: String(form.get("identity_id") ?? "").toLowerCase(),
              roleId: String(form.get("role_id") ?? ""),
              scopeType: String(form.get("scope_type") ?? ""),
              scopeId: String(form.get("scope_id") ?? "").trim() || null,
              catalogVersion: Number(form.get("catalog_version")),
            });
          } else {
            await refuseAccessRequestLine(repository, input);
          }
          redirect(response, "/admin/access-requests");
        } catch (error) {
          const status = error instanceof HttpInputError || error instanceof AccessRequestError ? error.status : 409;
          const code = error instanceof HttpInputError || error instanceof AccessRequestError ? error.code : "decision_conflict";
          writeHtml(response, status, "Décision non appliquée", `<h1>Décision non appliquée</h1><p>La demande, l’identité, le catalogue ou le rôle ne permet pas cette décision. Aucun changement partiel n’a été conservé.</p><p class="note">Code : ${escapeHtml(code)}</p><a class="button" href="/admin/access-requests">Retour</a>`);
        }
        return;
      }
      response.setHeader("allow", accessRequestRoute[1] ? "POST" : "GET");
      writeJson(response, 405, { error: "method_not_allowed" });
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
        session = await openCurrentSession(request);
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
        const [identities, applications, assignments, catalogs] = await Promise.all([
          repository.listIdentities(), repository.listApplications(), repository.listAllAssignments(),
          repository.listLatestApplicationAccessCatalogs(),
        ]);
        writeHtml(response, 200, "Utilisateurs et accès", renderAccessAdministration(identities, applications, assignments, catalogs));
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
        session = await openCurrentSession(request);
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
    if (url.pathname === "/internal/v1/notification-events") {
      if (request.method !== "POST") {
        response.setHeader("allow", "POST");
        writeJson(response, 405, { error: "method_not_allowed" });
        return;
      }
      let correlationId = randomUUID();
      try {
        const { payload, rawBody } = await readJson(request, maxBodyBytes);
        const authenticated = await authenticate(request, { rawBody });
        correlationId = authenticated?.correlationId || correlationId;
        const principal = authenticated ? { ...authenticated, correlationId } : null;
        const result = await receiveNotificationEvents({ repository, principal, payload });
        writeJson(response, result.status, result.body, correlationId);
      } catch (error) {
        if (error instanceof HttpInputError) writeJson(response, error.status, { error: error.code }, correlationId);
        else writeJson(response, 503, { error: "notification_ingress_unavailable" }, correlationId);
      }
      return;
    }
    if (url.pathname === "/internal/v1/application-sessions/revoke") {
      if (request.method !== "POST") {
        response.setHeader("allow", "POST");
        writeJson(response, 405, { error: "method_not_allowed" });
        return;
      }
      let correlationId = randomUUID();
      try {
        if (!sessionAuthority) throw new Error("session_authority_unavailable");
        const { payload, rawBody } = await readJson(request, maxBodyBytes);
        const principal = await authenticate(request, { rawBody });
        correlationId = principal?.correlationId || correlationId;
        const fields = Object.keys(payload ?? {});
        if (!principal || principal.audience !== principal.applicationId ||
            principal.applicationId !== payload?.application_id ||
            fields.some((field) => !["application_id", "identity_id", "session_id"].includes(field)) ||
            ![payload?.application_id, payload?.identity_id, payload?.session_id]
              .every((value) => typeof value === "string" && value)) {
          throw new HttpInputError(401, "authentication_required");
        }
        const result = await sessionAuthority.revokeForApplication({
          applicationId: payload.application_id,
          identityId: payload.identity_id,
          sessionId: payload.session_id,
          reason: "Déconnexion demandée dans N09 – Suivi des tâches",
        });
        if (!result.revoked) {
          writeJson(response, 404, { error: result.reasonCode }, correlationId);
          return;
        }
        writeJson(response, 200, { revoked: true, reason_code: result.reasonCode }, correlationId);
      } catch (error) {
        if (error instanceof HttpInputError) writeJson(response, error.status, { error: error.code }, correlationId);
        else writeJson(response, 503, { error: "session_registry_unavailable" }, correlationId);
      }
      return;
    }
    if (url.pathname === "/internal/v1/application-access-catalogs") {
      if (request.method !== "POST") {
        response.setHeader("allow", "POST");
        writeJson(response, 405, { error: "method_not_allowed" });
        return;
      }
      let correlationId = randomUUID();
      try {
        const { payload, rawBody } = await readJson(request, maxBodyBytes);
        const authenticated = await authenticate(request, { rawBody });
        correlationId = authenticated?.correlationId || correlationId;
        const principal = authenticated ? { ...authenticated, correlationId } : null;
        const result = await publishApplicationAccessCatalog({ repository, principal, payload });
        writeJson(response, result.status, result.body, correlationId);
      } catch (error) {
        if (error instanceof HttpInputError) writeJson(response, error.status, { error: error.code }, correlationId);
        else writeJson(response, 503, { error: "catalog_service_unavailable" }, correlationId);
      }
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
      const result = await evaluateAccessRequestAsync({ repository, principal, payload, sessionAuthority });
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
