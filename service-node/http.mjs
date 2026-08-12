import { randomUUID, timingSafeEqual } from "node:crypto";
import { evaluateAccessRequestAsync } from "./api.mjs";
import { createAuditEvent } from "./audit.mjs";
import { publishApplicationAccessCatalog } from "./application-access-catalog.mjs";
import { receiveNotificationEvents } from "./notification-ingress.mjs";
import { createLinkRequest } from "./federated-identity.mjs";
import { authorizeAccessAdministration } from "./access-admin.mjs";
import {
  ACCESS_DECISION_PERMISSION, authorizeAccessDecisionAdministration, grantAccessAssignment, revokeAccessAssignment,
} from "./access-decision-admin.mjs";
import { ADMIN_APPLICATION_ID, authorizeIdentityLinkAdministration } from "./identity-link-admin.mjs";
import { authorizeNotificationOperationsAdministration } from "./notification-operations-admin.mjs";
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
  response.end(`<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)} · N09 Administration</title><style>*{box-sizing:border-box}body{margin:0;background:#f3f6f4;color:#18221e;font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;padding:28px 0}.card{width:min(1100px,calc(100% - 36px));background:#fff;border:1px solid #dfe6e2;border-radius:18px;padding:34px;box-shadow:0 12px 40px #19392d14}.brand{color:#21825e;font-size:12px;font-weight:800;letter-spacing:1px}h1{font:600 31px Georgia,serif;margin:22px 0 12px}h2{font:600 21px Georgia,serif;margin:30px 0 12px}h3{margin:0 0 8px;font-size:17px}p{color:#5d6c65;line-height:1.6}.facts,.request{padding:16px;border-radius:10px;background:#f3f7f5;margin:20px 0}.facts strong,.request strong{color:#173e32}.button,button{display:inline-block;border:0;padding:12px 17px;border-radius:9px;background:#173e32;color:#fff;text-decoration:none;font-weight:bold;cursor:pointer}.button.secondary,button.secondary{background:#68756f}.actions{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:15px}.actions form,.grant{display:grid;gap:9px}.actions label,.grant label{font-size:13px;font-weight:700}.actions select,.actions input,.grant select,.grant input{width:100%;padding:10px;border:1px solid #bdcac4;border-radius:8px;background:#fff}.note,.muted{font-size:13px;color:#6c7a74}.expired{color:#9b391f;font-weight:700}nav{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:22px}.summary{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:24px 0}.metric{padding:18px;border:1px solid #dce6e1;border-radius:12px;background:#f8faf9}.metric strong{display:block;font-size:28px;color:#173e32}.directory{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.entry{padding:17px;border:1px solid #dce6e1;border-radius:12px}.entry p{margin:7px 0}.pill{display:inline-block;padding:4px 8px;border-radius:999px;background:#e4f3ec;color:#176044;font-size:12px;font-weight:800}.pill.inactive{background:#f2e8e4;color:#8a3b28}.permissions{margin:8px 0 0;padding-left:19px;color:#45564f}.permissions code,code{font-size:12px;word-break:break-word}.assignment{border-left:4px solid #21825e} @media(max-width:700px){.actions,.directory,.summary{grid-template-columns:1fr}.card{padding:24px}}</style></head><body><main class="card"><div class="brand">N09 · ADMINISTRATION · NSK TECH 09</div>${content}</main></body></html>`);
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
  return `<h1>Décider les accès</h1><p>Un octroi ne peut utiliser qu’un rôle actif publié par l’application. Son périmètre, sa justification et ses conditions sont inscrits dans le journal d’audit. Une application qui exige un profil métier doit ensuite confirmer ses propres prérequis à chaque requête.</p><div class="facts"><p><strong>Séparation stricte :</strong> Ad…5869 tokens truncated… writeHtml(response, 401, "Connexion requise", '<h1>Connexion requise</h1><p>Une session NSK valide est nécessaire.</p><a class="button" href="/">Se connecter</a>');
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
