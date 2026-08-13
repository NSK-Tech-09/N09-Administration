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
  response.end(`<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)} Â· N09 Administration</title><style>*{box-sizing:border-box}body{margin:0;background:#f3f6f4;color:#18221e;font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;padding:28px 0}.card{width:min(1100px,calc(100% - 36px));background:#fff;border:1px solid #dfe6e2;border-radius:18px;padding:34px;box-shadow:0 12px 40px #19392d14}.brand{color:#21825e;font-size:12px;font-weight:800;letter-spacing:1px}h1{font:600 31px Georgia,serif;margin:22px 0 12px}h2{font:600 21px Georgia,serif;margin:30px 0 12px}h3{margin:0 0 8px;font-size:17px}p{color:#5d6c65;line-height:1.6}.facts,.request{padding:16px;border-radius:10px;background:#f3f7f5;margin:20px 0}.facts strong,.request strong{color:#173e32}.button,button{display:inline-block;border:0;padding:12px 17px;border-radius:9px;background:#173e32;color:#fff;text-decoration:none;font-weight:bold;cursor:pointer}.button.secondary,button.secondary{background:#68756f}.actions{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:15px}.actions form,.grant{display:grid;gap:9px}.actions label,.grant label{font-size:13px;font-weight:700}.actions select,.actions input,.grant select,.grant input{width:100%;padding:10px;border:1px solid #bdcac4;border-radius:8px;background:#fff}.note,.muted{font-size:13px;color:#6c7a74}.expired{color:#9b391f;font-weight:700}nav{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:22px}.summary{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:24px 0}.metric{padding:18px;border:1px solid #dce6e1;border-radius:12px;background:#f8faf9}.metric strong{display:block;font-size:28px;color:#173e32}.directory{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.entry{padding:17px;border:1px solid #dce6e1;border-radius:12px}.entry p{margin:7px 0}.pill{display:inline-block;padding:4px 8px;border-radius:999px;background:#e4f3ec;color:#176044;font-size:12px;font-weight:800}.pill.inactive{background:#f2e8e4;color:#8a3b28}.permissions{margin:8px 0 0;padding-left:19px;color:#45564f}.permissions code,code{font-size:12px;word-break:break-word}.assignment{border-left:4px solid #21825e} @media(max-width:700px){.actions,.directory,.summary{grid-template-columns:1fr}.card{padding:24px}}</style></head><body><main class="card"><div class="brand">N09 Â· ADMINISTRATION Â· NSK TECH 09</div>${content}</main></body></html>`);
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
    `<option value="${escapeHtml(identity.identityId)}">${escapeHtml(identity.displayName)} â€” ${escapeHtml(identity.email)}</option>`
  ).join("");
  const cards = requests.map((request) => {
    const expired = new Date(request.expiresAt) <= now;
    const approval = expired ? '<p class="expired">Cette demande est expirÃ©e et ne peut plus Ãªtre approuvÃ©e.</p>' :
      `<form method="post" action="/admin/link-requests/${escapeHtml(request.requestId)}/approve"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><label>IdentitÃ© NSK cible<select name="target_identity_id" required><option value="">SÃ©lectionnerâ€¦</option>${identityOptions}</select></label><label>Justification<input name="justification" maxlength="500" required placeholder="Pourquoi ce rattachement est lÃ©gitime"></label><button type="submit">Approuver</button></form>`;
    return `<section class="request"><h2>${escapeHtml(request.displayNameHint || "IdentitÃ© externe")}</h2><p><strong>Fournisseur :</strong> ${escapeHtml(request.providerKey)}<br><strong>Adresse prÃ©sentÃ©e :</strong> ${escapeHtml(request.emailHint || "non communiquÃ©e")}<br><strong>DemandÃ©e le :</strong> ${escapeHtml(formatDate(request.requestedAt))}<br><strong>Ã‰chÃ©ance :</strong> ${escapeHtml(formatDate(request.expiresAt))}<br><span class="note">RÃ©fÃ©rence : ${escapeHtml(request.requestId)}</span></p><div class="actions">${approval}<form method="post" action="/admin/link-requests/${escapeHtml(request.requestId)}/reject"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><label>Motif du refus<input name="justification" maxlength="500" required placeholder="Pourquoi cette demande est refusÃ©e"></label><button class="secondary" type="submit">Refuser</button></form></div></section>`;
  }).join("");
  return `<h1>Demandes de rattachement</h1><p>Chaque dÃ©cision est nominative, justifiÃ©e et inscrite dans le journal dâ€™audit. Aucun rÃ´le ni droit applicatif nâ€™est accordÃ© par un rattachement.</p>${cards || '<div class="facts"><p>Aucune demande en attente.</p></div>'}<nav><a class="button secondary" href="/">Retour Ã  lâ€™accueil</a><form method="post" action="/auth/logout"><button class="secondary" type="submit">Fermer la session</button></form></nav>`;
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
    `<article class="entry"><h3>${escapeHtml(identity.displayName)}</h3><p>${escapeHtml(identity.email)}</p><p>${statusPill(identity.status)}</p><p class="muted">IdentitÃ© : <code>${escapeHtml(identity.identityId)}</code></p></article>`
  ).join("");
  const applicationCards = applications.map((application) => {
    const catalog = catalogByApplicationId.get(application.applicationId);
    if (!catalog) return `<article class="entry"><h3>${escapeHtml(application.displayName)}</h3><p>${statusPill(application.status)} Â· inscription ${escapeHtml(application.registrationPolicy)}</p><div class="facts"><p><strong>Catalogue absent :</strong> aucun nouvel octroi ne doit Ãªtre ouvert pour cette application.</p></div><p class="muted">Application : <code>${escapeHtml(application.applicationId)}</code></p></article>`;
    const roles = catalog.roles.map((role) => `<li><code>${escapeHtml(role.role_id)}</code> â€” ${escapeHtml(role.displayName)} (${escapeHtml(role.status)})</li>`).join("");
    const provisioning = catalog.provisioning.mode === "central_identity_only"
      ? "identitÃ© centrale, sans profil applicatif supplÃ©mentaire"
      : catalog.provisioning.mode === "preexisting_profile_required"
        ? "profil applicatif prÃ©existant et confirmation de lâ€™application requis"
        : "crÃ©ation automatique dÃ©clarÃ©e par lâ€™application";
    return `<article class="entry"><h3>${escapeHtml(application.displayName)}</h3><p>${statusPill(application.status)} Â· inscription ${escapeHtml(application.registrationPolicy)}</p><p><strong>Catalogue v${escapeHtml(catalog.catalogVersion)}</strong> Â· ${escapeHtml(provisioning)}</p><ul class="permissions">${roles}</ul><p class="muted">Application : <code>${escapeHtml(application.applicationId)}</code><br>Empreinte : <code>${escapeHtml(catalog.catalogHash)}</code></p></article>`;
  }).join("");
  const assignmentCards = assignments.map((assignment) => {
    const identity = identityById.get(assignment.subjectId);
    const application = applicationById.get(assignment.applicationId);
    const scope = assignment.scopeType ? `${assignment.scopeType} : ${assignment.scopeId || "non dÃ©fini"}` : "global";
    const permissions = assignment.permissions.map((permission) => `<li><code>${escapeHtml(permission)}</code></li>`).join("");
    return `<article class="entry assignment"><h3>${escapeHtml(identity?.displayName || assignment.subjectId)} â†’ ${escapeHtml(application?.displayName || assignment.applicationId)}</h3><p><strong>${escapeHtml(assignment.roleId)}</strong> Â· ${statusPill(assignment.status)} Â· pÃ©rimÃ¨tre ${escapeHtml(scope)}</p><ul class="permissions">${permissions || "<li>Aucune permission</li>"}</ul><p class="muted">Motif : ${escapeHtml(assignment.reason || "non renseignÃ©")} Â· version ${escapeHtml(assignment.version)}</p></article>`;
  }).join("");
  return `<h1>Utilisateurs et accÃ¨s</h1><p>Vue centrale en lecture seule des identitÃ©s, applications, catalogues publiÃ©s et affectations. Cette page nâ€™accorde, ne modifie et ne rÃ©voque aucun droit.</p><div class="summary"><div class="metric"><strong>${activeIdentities}</strong>identitÃ©s actives</div><div class="metric"><strong>${activeApplications}</strong>applications actives</div><div class="metric"><strong>${activeAssignments}</strong>affectations actives</div></div><h2>IdentitÃ©s</h2><div class="directory">${identityCards || '<div class="facts"><p>Aucune identitÃ© enregistrÃ©e.</p></div>'}</div><h2>Applications et catalogues</h2><div class="directory">${applicationCards || '<div class="facts"><p>Aucune application enregistrÃ©e.</p></div>'}</div><h2>Affectations</h2><div class="directory">${assignmentCards || '<div class="facts"><p>Aucune affectation enregistrÃ©e.</p></div>'}</div><nav><a class="button secondary" href="/">Retour Ã  lâ€™accueil</a><a class="button secondary" href="/admin/link-requests">Rattachements</a><form method="post" action="/auth/logout"><button class="secondary" type="submit">Fermer la session</button></form></nav>`;
}

function renderAccessDecisionAdministration(identities, applications, assignments, catalogs, csrf) {
  const identityById = new Map(identities.map((identity) => [identity.identityId, identity]));
  const applicationById = new Map(applications.map((application) => [application.applicationId, application]));
  const activeIdentityOptions = identities.filter((identity) => identity.status === "active").map((identity) =>
    `<option value="${escapeHtml(identity.identityId)}">${escapeHtml(identity.displayName)} â€” ${escapeHtml(identi×m4êÚ$z{-®éÜj×‡&WVW7BÂÖ„&öG”'—FW2“°¢–b‚6fTWVÂ†f÷&ÒævWB‚&77&b"’Â6W76–öâæ77&b’’F‡&÷ræWr‡GG–çWDW'&÷"ƒC2Â&–çfÆ–Eö77&b"“°¢6öç7BW‡V7FVEfW'6–öâÒçVÖ&W"†f÷&ÒævWB‚&W‡V7FVE÷fW'6–öâ"’“°¢6öç7B§W7F–f–6F–öâÒ7G&–ær†f÷&ÒævWB‚&§W7F–f–6F–öâ"’óò""’çG&–Ò‚“°¢–b‚çVÖ&W"æ—4–çFVvW"†W‡V7FVEfW'6–öâ’ÇÂW‡V7FVEfW'6–öâÂ’F‡&÷ræWr‡GG–çWDW'&÷"ƒCÂ&–çfÆ–Eö76–væÖVçE÷fW'6–öâ"“°¢–b†§W7F–f–6F–öâæÆVæwF‚Â#ÇÂ§W7F–f–6F–öâæÆVæwF‚âS’F‡&÷ræWr‡GG–çWDW'&÷"ƒCÂ&–çfÆ–Eö§W7F–f–6F–öâ"“°¢v—B&Wfö¶T66W7476–væÖVçB‡&W÷6—F÷'’Â°¢76–væÖVçD–C¢66W75&Wfö6F–öå&÷WFU³ÒçFôÆ÷vW$66R‚’À¢W‡V7FVEfW'6–öâÀ¢÷W&F÷$–FVçF—G”–C¢6W76–öâæ–FVçF—G”–BÀ¢§W7F–f–6F–öâÀ¢Ò“°¢&VF—&V7B‡&W7öç6RÂ"öFÖ–âö66W72ÖFV6—6–öç2"“°¢Ò6F6‚†W'&÷"’°¢–b†W'&÷"–ç7Fæ6Vöb‡GG–çWDW'&÷"’°¢w&—FT‡FÖÂ‡&W7öç6RÂW'&÷"ç7FGW2Â%,:—fö6F–öâæöâÆ—\:–R"ÂÆƒå,:—fö6F–öâæöâÆ—\:–SÂöƒãÇäÆFVÖæFRW7B–çfÆ–FRâV7Vâ6<:‡2î(	–:—L:’ÖöF–fœ:’ãÂ÷ãÇ6Æ73Ò&æ÷FR#ä6öFR¢G¶W66T‡FÖÂ†W'&÷"æ6öFR—ÓÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"öFÖ–âö66W72ÖFV6—6–öç2#å&WF÷W#Âöæ“°¢ÒVÇ6R°¢6öç6öÆRæW'&÷"„¥4ôâç7G&–æv–g’‡²WfVçC¢&66W75÷&Wfö6F–öåöf–ÆVB"Â&V6öã¢'&W÷6—F÷'•÷&V¦V7FVEöFV6—6–öâ"Ò’“°¢w&—FT‡FÖÂ‡&W7öç6RÂC’Â%,:—fö6F–öâæöâÆ—\:–R"ÂsÆƒå,:—fö6F–öâæöâÆ—\:–SÂöƒãÇäÎ(	–ffV7FF–öâ6†æ|:’Âî(	–W7BÇW27F—fR÷R6öâ&WG&—B&VÌ:‡fRN(	—VæRv÷WfW&ææ6RL:–Fœ:–RâV7Vâ6†ævVÖVçB'F–VÂî(	–:—L:’6öç6W'l:’ãÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"öFÖ–âö66W72ÖFV6—6–öç2#å&WF÷W#Âöâr“°¢Ğ¢Ğ¢&WGW&ã°¢Ğ¢&W7öç6Rç6WD†VFW"‚&ÆÆ÷r"Â66W74FV6—6–öå&ö÷Bò$tUB"¢%õ5B"“°¢w&—FT§6öâ‡&W7öç6RÂCRÂ²W'&÷#¢&ÖWF†öEöæ÷EöÆÆ÷vVB"Ò“°¢&WGW&ã°¢Ğ¢–b‡W&ÂçF†æÖRÓÓÒ"öFÖ–âö66W72"’°¢–b‡&WVW7BæÖWF†öBÓÒ$tUB"’°¢&W7öç6Rç6WD†VFW"‚&ÆÆ÷r"Â$tUB"“°¢w&—FT§6öâ‡&W7öç6RÂCRÂ²W'&÷#¢&ÖWF†öEöæ÷EöÆÆ÷vVB"Ò“°¢&WGW&ã°¢Ğ¢ÆWB6W76–öã°¢G'’°¢–b‚ö–F46öæf–r’F‡&÷ræWrW'&÷"‚&ö–F5öæ÷Eö6öæf–wW&VB"“°¢6W76–öâÒ÷Vä7W'&VçE6W76–öâ‡&WVW7B“°¢Ò6F6‚°¢w&—FT‡FÖÂ‡&W7öç6RÂCÂ$6öææW†–öâ&WV—6R"ÂsÆƒä6öææW†–öâ&WV—6SÂöƒãÇåVæR6W76–öâå4²fÆ–FRW7Bì:–6W76—&RãÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"ò#å6R6öææV7FW#Âöâr“°¢&WGW&ã°¢Ğ¢–b‡6W76–öâç7FGW2ÓÒ&WF†VçF–6FVB"ÇÂ6W76–öâæ–FVçF—G”–BÇÂ6W76–öâæ77&b’°¢w&—FT‡FÖÂ‡&W7öç6RÂCÂ$æ÷WfVÆÆR6öææW†–öâ&WV—6R"ÂsÆƒäæ÷WfVÆÆR6öææW†–öâ&WV—6SÂöƒãÇäfW&ÖRV—2&Væ÷WfVÆÆRF6W76–öâf–âN(	–6<:–FW":Î(	–FÖ–æ—7G&F–öâ<:–7W&—<:–RãÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"ò#å&WF÷W#Âöâr“°¢&WGW&ã°¢Ğ¢ÆWB66W73°¢G'’°¢66W72Òv—BWF†÷&—¦T66W74FÖ–æ—7G&F–öâ‡&W÷6—F÷'’Â6W76–öâæ–FVçF—G”–B“°¢Ò6F6‚°¢6öç6öÆRæW'&÷"„¥4ôâç7G&–æv–g’‡²WfVçC¢&66W75öFÖ–æ—7G&F–öå÷Væf–Æ&ÆR"Â&V6öã¢&WF†÷&—¦F–öå÷&W÷6—F÷'•öf–ÇW&R"Ò’“°¢w&—FT‡FÖÂ‡&W7öç6RÂS2Â$FÖ–æ—7G&F–öâ–æF—7öæ–&ÆR"ÂsÆƒäFÖ–æ—7G&F–öâÖöÖVçFì:–ÖVçB–æF—7öæ–&ÆSÂöƒãÇäV7VæRFöæì:–RN(	–6<:‡2æRWWB:§G&Rl:—&–fœ:–R÷W"ÆRÖöÖVçBãÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"ò#å&WF÷W#Âöâr“°¢&WGW&ã°¢Ğ¢–b‚66W72æÆÆ÷vVB’°¢w&—FT‡FÖÂ‡&W7öç6RÂC2Â$6<:‡2&VgW<:’"ÂsÆƒä6<:‡2&VgW<:“ÂöƒãÇä6WGFR–FVçF—L:’æR÷7<:†FR2ÆW&Ö—76–öâL:–Fœ:–R:Æ6öç7VÇFF–öâFW26<:‡2âV7VâG&ö—B–×Æ–6—FRî(	–W7B66÷&L:’ãÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"ò#å&WF÷W#Âöâr“°¢&WGW&ã°¢Ğ¢G'’°¢6öç7B¶–FVçF—F–W2ÂÆ–6F–öç2Â76–væÖVçG2Â6FÆöw5ÒÒv—B&öÖ—6RæÆÂ…°¢&W÷6—F÷'’æÆ—7D–FVçF—F–W2‚’Â&W÷6—F÷'’æÆ—7DÆ–6F–öç2‚’Â&W÷6—F÷'’æÆ—7DÆÄ76–væÖVçG2‚’À¢&W÷6—F÷'’æÆ—7DÆFW7DÆ–6F–öä66W746FÆöw2‚’À¢Ò“°¢w&—FT‡FÖÂ‡&W7öç6RÂ#Â%WF–Æ—6FWW'2WB6<:‡2"Â&VæFW$66W74FÖ–æ—7G&F–öâ†–FVçF—F–W2ÂÆ–6F–öç2Â76–væÖVçG2Â6FÆöw2’“°¢Ò6F6‚°¢6öç6öÆRæW'&÷"„¥4ôâç7G&–æv–g’‡²WfVçC¢&66W75öFÖ–æ—7G&F–öå÷Væf–Æ&ÆR"Â&V6öã¢&Æ—7F–æu÷&W÷6—F÷'•öf–ÇW&R"Ò’“°¢w&—FT‡FÖÂ‡&W7öç6RÂS2Â$FÖ–æ—7G&F–öâ–æF—7öæ–&ÆR"ÂsÆƒäFÖ–æ—7G&F–öâÖöÖVçFì:–ÖVçB–æF—7öæ–&ÆSÂöƒãÇäÆR&Vv—7G&Rî(	–2R:§G&R6öç7VÇL:’âV7Vâ6<:‡2î(	–:—L:’ÖöF–fœ:’ãÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"ò#å&WF÷W#Âöâr“°¢Ğ¢&WGW&ã°¢Ğ¢6öç7BFÖ–å&÷WFRÒW&ÂçF†æÖRæÖF6‚‚õåÂöFÖ–åÂöÆ–æ²×&WVW7G2ƒó¥Âò…³Ó–Öe×³‡ÒÕ³Ó–Öe×³GÒÕ³Ó–Öe×³GÒÕ³Ó–Öe×³GÒÕ³Ó–Öe×³'Ò•Âò†&÷fWÇ&V¦V7B’“òBö’“°¢–b†FÖ–å&÷WFR’°¢ÆWB6W76–öã°¢G'’°¢–b‚ö–F46öæf–r’F‡&÷ræWrW'&÷"‚&ö–F5öæ÷Eö6öæf–wW&VB"“°¢6W76–öâÒ÷Vä7W'&VçE6W76–öâ‡&WVW7B“°¢Ò6F6‚°¢w&—FT‡FÖÂ‡&W7öç6RÂCÂ$6öææW†–öâ&WV—6R"ÂsÆƒä6öææW†–öâ&WV—6SÂöƒãÇåVæR6W76–öâå4²fÆ–FRW7Bì:–6W76—&RãÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"ò#å6R6öææV7FW#Âöâr“°¢&WGW&ã°¢Ğ¢–b‡6W76–öâç7FGW2ÓÒ&WF†VçF–6FVB"ÇÂ6W76–öâæ–FVçF—G”–BÇÂ6W76–öâæ77&b’°¢w&—FT‡FÖÂ‡&W7öç6RÂCÂ$æ÷WfVÆÆR6öææW†–öâ&WV—6R"ÂsÆƒäæ÷WfVÆÆR6öææW†–öâ&WV—6SÂöƒãÇäfW&ÖRV—2&Væ÷WfVÆÆRF6W76–öâf–âN(	–6<:–FW":Î(	–FÖ–æ—7G&F–öâ<:–7W&—<:–RãÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"ò#å&WF÷W#Âöâr“°¢&WGW&ã°¢Ğ¢ÆWB66W73°¢G'’°¢66W72Òv—BWF†÷&—¦T–FVçF—G”Æ–æ´FÖ–æ—7G&F–öâ‡&W÷6—F÷'’Â6W76–öâæ–FVçF—G”–B“°¢Ò6F6‚°¢6öç6öÆRæW'&÷"„¥4ôâç7G&–æv–g’‡²WfVçC¢&Æ–æµöFÖ–æ—7G&F–öå÷Væf–Æ&ÆR"Â&V6öã¢&WF†÷&—¦F–öå÷&W÷6—F÷'•öf–ÇW&R"Ò’“°¢w&—FT‡FÖÂ‡&W7öç6RÂS2Â$FÖ–æ—7G&F–öâ–æF—7öæ–&ÆR"ÂsÆƒäFÖ–æ—7G&F–öâÖöÖVçFì:–ÖVçB–æF—7öæ–&ÆSÂöƒãÇäV7VæRL:–6—6–öâî(	–:—L:’Æ—\:–Râ,:–W76–RÆ÷'7VRÆR&Vv—7G&R6VçG&Â6W&F—7öæ–&ÆRãÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"ò#å&WF÷W#Âöâr“°¢&WGW&ã°¢Ğ¢–b‚66W72æÆÆ÷vVB’°¢w&—FT‡FÖÂ‡&W7öç6RÂC2Â$6<:‡2&VgW<:’"ÂsÆƒä6<:‡2&VgW<:“ÂöƒãÇä6WGFR–FVçF—L:’æR÷7<:†FR2ÆW&Ö—76–öâFÖ–æ—7G&F—fRL:–Fœ:–RâV7VâG&ö—B–×Æ–6—FRî(	–W7B66÷&L:’ãÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"ò#å&WF÷W#Âöâr“°¢&WGW&ã°¢Ğ¢–b‚FÖ–å&÷WFU³Òbb&WVW7BæÖWF†öBÓÓÒ$tUB"’°¢G'’°¢6öç7B·&WVW7G2Â–FVçF—F–W5ÒÒv—B&öÖ—6RæÆÂ…°¢&W÷6—F÷'’æÆ—7DÆ–æµ&WVW7G2‚'VæF–ær"’Â&W÷6—F÷'’æÆ—7D–FVçF—F–W2‚&7F—fR"’À¢Ò“°¢w&—FT‡FÖÂ‡&W7öç6RÂ#Â%&GF6†VÖVçG2"Â&VæFW$Æ–æµ&WVW7DFÖ–æ—7G&F–öâ‡&WVW7G2Â–FVçF—F–W2Â6W76–öâæ77&b’“°¢Ò6F6‚°¢6öç6öÆRæW'&÷"„¥4ôâç7G&–æv–g’‡²WfVçC¢&Æ–æµöFÖ–æ—7G&F–öå÷Væf–Æ&ÆR"Â&V6öã¢&Æ—7F–æu÷&W÷6—F÷'•öf–ÇW&R"Ò’“°¢w&—FT‡FÖÂ‡&W7öç6RÂS2Â$FÖ–æ—7G&F–öâ–æF—7öæ–&ÆR"ÂsÆƒäFÖ–æ—7G&F–öâÖöÖVçFì:–ÖVçB–æF—7öæ–&ÆSÂöƒãÇäÆR&Vv—7G&Rî(	–2R:§G&R6öç7VÇL:’âV7VæRL:–6—6–öâî(	–:—L:’Æ—\:–RãÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"ò#å&WF÷W#Âöâr“°¢Ğ¢&WGW&ã°¢Ğ¢–b†FÖ–å&÷WFU³Òbb&WVW7BæÖWF†öBÓÓÒ%õ5B"’°¢G'’°¢6öç7Bf÷&ÒÒv—B&VDf÷&Ò‡&WVW7BÂÖ„&öG”'—FW2“°¢–b‚6fTWVÂ†f÷&ÒævWB‚&77&b"’Â6W76–öâæ77&b’’F‡&÷ræWr‡GG–çWDW'&÷"ƒC2Â&–çfÆ–Eö77&b"“°¢6öç7B&WVW7D–BÒFÖ–å&÷WFU³ÒçFôÆ÷vW$66R‚“°¢6öç7BFV6—6–öâÒFÖ–å&÷WFU³%ÒçFôÆ÷vW$66R‚“°¢6öç7B§W7F–f–6F–öâÒ7G&–ær†f÷&ÒævWB‚&§W7F–f–6F–öâ"’óò""’çG&–Ò‚“°¢–b‚§W7F–f–6F–öâÇÂ§W7F–f–6F–öâæÆVæwF‚âS’F‡&÷ræWr‡GG–çWDW'&÷"ƒCÂ&–çfÆ–Eö§W7F–f–6F–öâ"“°¢6öç7BÆ–æµ&WVW7BÒv—B&W÷6—F÷'’ævWDÆ–æµ&WVW7B‡&WVW7D–B“°¢–b‚Æ–æµ&WVW7B’F‡&÷ræWr‡GG–çWDW'&÷"ƒCBÂ&Æ–æµ÷&WVW7Eöæ÷Eöf÷VæB"“°¢6öç7B6÷'&VÆF–öä–BÒ&æFöÕUT”B‚“°¢–b†FV6—6–öâÓÓÒ&&÷fR"’°¢6öç7BF&vWD–FVçF—G”–BÒ7G&–ær†f÷&ÒævWB‚'F&vWEö–FVçF—G•ö–B"’óò""’çG&–Ò‚“°¢–b‚F&vWD–FVçF—G”–B’F‡&÷ræWr‡GG–çWDW'&÷"ƒCÂ'F&vWEö–FVçF—G•÷&WV—&VB"“°¢v—B&W÷6—F÷'’æ&÷fTÆ–æµ&WVW7B‡&WVW7D–BÂF&vWD–FVçF—G”–BÂ6W76–öâæ–FVçF—G”–BÂ§W7F–f–6F–öâÂ7&VFTVF—DWfVçB‡°¢7F–öã¢&W‡FW&æÅö–FVçF—G’æÆ–æµö&÷fVB"Â&W7VÇC¢'7V66W72"Â6÷W&6S¢&FÖ–æ—7G&F–öâ×V’"À¢6÷'&VÆF–öä–BÂ7F÷$–C¢6W76–öâæ–FVçF—G”–BÂ7V&¦V7D–C¢F&vWD–FVçF—G”–BÀ¢&Wf–÷W5fÇVS¢²&WVW7Eö–C¢&WVW7D–BÂ7FGW3¢'VæF–ær"ÒÀ¢æWufÇVS¢²&WVW7Eö–C¢&WVW7D–BÂ7FGW3¢&&÷fVB"ÂF&vWEö–FVçF—G•ö–C¢F&vWD–FVçF—G”–BÒÀ¢§W7F–f–6F–öâÀ¢Ò’“°¢ÒVÇ6R°¢v—B&W÷6—F÷'’ç&V¦V7DÆ–æµ&WVW7B‡&WVW7D–BÂ6W76–öâæ–FVçF—G”–BÂ§W7F–f–6F–öâÂ7&VFTVF—DWfVçB‡°¢7F–öã¢&W‡FW&æÅö–FVçF—G’æÆ–æµ÷&V¦V7FVB"Â&W7VÇC¢'7V66W72"Â6÷W&6S¢&FÖ–æ—7G&F–öâ×V’"À¢6÷'&VÆF–öä–BÂ7F÷$–C¢6W76–öâæ–FVçF—G”–BÀ¢&Wf–÷W5fÇVS¢²&WVW7Eö–C¢&WVW7D–BÂ7FGW3¢'VæF–ær"ÒÀ¢æWufÇVS¢²&WVW7Eö–C¢&WVW7D–BÂ7FGW3¢'&V¦V7FVB"ÒÂ§W7F–f–6F–öâÀ¢Ò’“°¢Ğ¢&VF—&V7B‡&W7öç6RÂ"öFÖ–âöÆ–æ²×&WVW7G2"“°¢Ò6F6‚†W'&÷"’°¢–b†W'&÷"–ç7Fæ6Vöb‡GG–çWDW'&÷"’°¢w&—FT‡FÖÂ‡&W7öç6RÂW'&÷"ç7FGW2Â$L:–6—6–öâæöâÆ—\:–R"ÂÆƒäL:–6—6–öâæöâÆ—\:–SÂöƒãÇäÆFVÖæFRW7B–çfÆ–FR÷Rî(	–W7BÇW2F—7öæ–&ÆRâV7Vâ6†ævVÖVçB'F–VÂî(	–:—L:’6öç6W'l:’ãÂ÷ãÇ6Æ73Ò&æ÷FR#ä6öFR¢G¶W66T‡FÖÂ†W'&÷"æ6öFR—ÓÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"öFÖ–âöÆ–æ²×&WVW7G2#å&WF÷W#Âöæ“°¢ÒVÇ6R°¢6öç6öÆRæW'&÷"„¥4ôâç7G&–æv–g’‡²WfVçC¢&Æ–æµöFV6—6–öåöf–ÆVB"Â&V6öã¢'&W÷6—F÷'•÷&V¦V7FVEöFV6—6–öâ"Ò’“°¢w&—FT‡FÖÂ‡&W7öç6RÂC’Â$L:–6—6–öâæöâÆ—\:–R"ÂsÆƒäL:–6—6–öâæöâÆ—\:–SÂöƒãÇäÆFVÖæFRæRWWB2:§G&RG&—L:–RFç26öâ:—FB7GVVÂâV7Vâ6†ævVÖVçB'F–VÂî(	–:—L:’6öç6W'l:’ãÂ÷ãÆ6Æ73Ò&'WGFöâ"‡&VcÒ"öFÖ–âöÆ–æ²×&WVW7G2#å&WF÷W#Âöâr“°¢Ğ¢Ğ¢&WGW&ã°¢Ğ¢&W7öç6Rç6WD†VFW"‚&ÆÆ÷r"ÂFÖ–å&÷WFU³Òò%õ5B"¢$tUB"“°¢w&—FT§6öâ‡&W7öç6RÂCRÂ²W'&÷#¢&ÖWF†öEöæ÷EöÆÆ÷vVB"Ò“°¢&WGW&ã°¢Ğ¢–b‡W&ÂçF†æÖRÓÓÒ"ö–çFW&æÂ÷cöæ÷F–f–6F–öâÖWfVçG2"’°¢–b‡&WVW7BæÖWF†öBÓÒ%õ5B"’°¢&W7öç6Rç6WD†VFW"‚&ÆÆ÷r"Â%õ5B"“°¢w&—FT§6öâ‡&W7öç6RÂCRÂ²W'&÷#¢&ÖWF†öEöæ÷EöÆÆ÷vVB"Ò“°¢&WGW&ã°¢Ğ¢ÆWB6÷'&VÆF–öä–BÒ&æFöÕUT”B‚“°¢G'’°¢6öç7B²–ÆöBÂ&t&öG’ÒÒv—B&VD§6öâ‡&WVW7BÂÖ„&öG”'—FW2“°¢6öç7BWF†VçF–6FVBÒv—BWF†VçF–6FR‡&WVW7BÂ²&t&öG’Ò“°¢6÷'&VÆF–öä–BÒWF†VçF–6FVCòæ6÷'&VÆF–öä–BÇÂ6÷'&VÆF–öä–C°¢6öç7B&–æ6—ÂÒWF†VçF–6FVBò²ââæWF†VçF–6FVBÂ6÷'&VÆF–öä–BÒ¢çVÆÃ°¢6öç7B&W7VÇBÒv—B&V6V—fTæ÷F–f–6F–öäWfVçG2‡²&W÷6—F÷'’Â&–æ6—ÂÂ–ÆöBÒ“°¢w&—FT§6öâ‡&W7öç6RÂ&W7VÇBç7FGW2Â&W7VÇBæ&öG’Â6÷'&VÆF–öä–B“°¢Ò6F6‚†W'&÷"’°¢–b†W'&÷"–ç7Fæ6Vöb‡GG–çWDW'&÷"’w&—FT§6öâ‡&W7öç6RÂW'&÷"ç7FGW2Â²W'&÷#¢W'&÷"æ6öFRÒÂ6÷'&VÆF–öä–B“°¢VÇ6Rw&—FT§6öâ‡&W7öç6RÂS2Â²W'&÷#¢&æ÷F–f–6F–öåö–æw&W75÷Væf–Æ&ÆR"ÒÂ6÷'&VÆF–öä–B“°¢Ğ¢&WGW&ã°¢Ğ¢–b‡W&ÂçF†æÖRÓÓÒ"ö–çFW&æÂ÷cöÆ–6F–öâ×6W76–öç2÷&Wfö¶R"’°¢–b‡&WVW7BæÖWF†öBÓÒ%õ5B"’°¢&W7öç6Rç6WD†VFW"‚&ÆÆ÷r"Â%õ5B"“°¢w&—FT§6öâ‡&W7öç6RÂCRÂ²W'&÷#¢&ÖWF†öEöæ÷EöÆÆ÷vVB"Ò“°¢&WGW&ã°¢Ğ¢ÆWB6÷'&VÆF–öä–BÒ&æFöÕUT”B‚“°¢G'’°¢–b‚6W76–öäWF†÷&—G’’F‡&÷ræWrW'&÷"‚'6W76–öåöWF†÷&—G•÷Væf–Æ&ÆR"“°¢6öç7B²–ÆöBÂ&t&öG’ÒÒv—B&VD§6öâ‡&WVW7BÂÖ„&öG”'—FW2“°¢6öç7B&–æ6—ÂÒv—BWF†VçF–6FR‡&WVW7BÂ²&t&öG’Ò“°¢6÷'&VÆF–öä–BÒ&–æ6—Ãòæ6÷'&VÆF–öä–BÇÂ6÷'&VÆF–öä–C°¢6öç7Bf–VÆG2Òö&¦V7Bæ¶W—2‡–ÆöBóò·Ò“°¢–b‚&–æ6—ÂÇÂ&–æ6—ÂæVF–Væ6RÓÒ&–æ6—ÂæÆ–6F–öä–BÇÀ¢&–æ6—ÂæÆ–6F–öä–BÓÒ–ÆöCòæÆ–6F–öåö–BÇÀ¢f–VÆG2ç6öÖR‚†f–VÆB’Óâ²&Æ–6F–öåö–B"Â&–FVçF—G•ö–B"Â'6W76–öåö–B%Òæ–æ6ÇVFW2†f–VÆB’’ÇÀ¢·–ÆöCòæÆ–6F–öåö–BÂ–ÆöCòæ–FVçF—G•ö–BÂ–ÆöCòç6W76–öåö–EĞ¢æWfW'’‚‡fÇVR’ÓâG—VöbfÇVRÓÓÒ'7G&–ær"bbfÇVR’’°¢F‡&÷ræWr‡GG–çWDW'&÷"ƒCÂ&WF†VçF–6F–öå÷&WV—&VB"“°¢Ğ¢6öç7B&W7VÇBÒv—B6W76–öäWF†÷&—G’ç&Wfö¶Tf÷$Æ–6F–öâ‡°¢Æ–6F–öä–C¢–ÆöBæÆ–6F–öåö–BÀ¢–FVçF—G”–C¢–ÆöBæ–FVçF—G•ö–BÀ¢6W76–öä–C¢–ÆöBç6W76–öåö–BÀ¢&V6öã¢$L:–6öææW†–öâFVÖæL:–RFç2ã’(	27V—f’FW2L:&6†W2"À¢Ò“°¢–b‚&W7VÇBç&Wfö¶VB’°¢w&—FT§6öâ‡&W7öç6RÂCBÂ²W'&÷#¢&W7VÇBç&V6öä6öFRÒÂ6÷'&VÆF–öä–B“°¢&WGW&ã°¢Ğ¢w&—FT§6öâ‡&W7öç6RÂ#Â²&Wfö¶VC¢G'VRÂ&V6öåö6öFS¢&W7VÇBç&V6öä6öFRÒÂ6÷'&VÆF–öä–B“°¢Ò6F6‚†W'&÷"’°¢–b†W'&÷"–ç7Fæ6Vöb‡GG–çWDW'&÷"’w&—FT§6öâ‡&W7öç6RÂW'&÷"ç7FGW2Â²W'&÷#¢W'&÷"æ6öFRÒÂ6÷'&VÆF–öä–B“°¢VÇ6Rw&—FT§6öâ‡&W7öç6RÂS2Â²W'&÷#¢'6W76–öå÷&Vv—7G'•÷Væf–Æ&ÆR"ÒÂ6÷'&VÆF–öä–B“°¢Ğ¢&WGW&ã°¢Ğ¢–b‡W&ÂçF†æÖRÓÓÒ"ö–çFW&æÂ÷cöÆ–6F–öâÖ66W72Ö6FÆöw2"’°¢–b‡&WVW7BæÖWF†öBÓÒ%õ5B"’°¢&W7öç6Rç6WD†VFW"‚&ÆÆ÷r"Â%õ5B"“°¢w&—FT§6öâ‡&W7öç6RÂCRÂ²W'&÷#¢&ÖWF†öEöæ÷EöÆÆ÷vVB"Ò“°¢&WGW&ã°¢Ğ¢ÆWB6÷'&VÆF–öä–BÒ&æFöÕUT”B‚“°¢G'’°¢6öç7B²–ÆöBÂ&t&öG’ÒÒv—B&VD§6öâ‡&WVW7BÂÖ„&öG”'—FW2“°¢6öç7BWF†VçF–6FVBÒv—BWF†VçF–6FR‡&WVW7BÂ²&t&öG’Ò“°¢6÷'&VÆF–öä–BÒWF†VçF–6FVCòæ6÷'&VÆF–öä–BÇÂ6÷'&VÆF–öä–C°¢6öç7B&–æ6—ÂÒWF†VçF–6FVBò²ââæWF†VçF–6FVBÂ6÷'&VÆF–öä–BÒ¢çVÆÃ°¢6öç7B&W7VÇBÒv—BV&Æ—6„Æ–6F–öä66W746FÆör‡²&W÷6—F÷'’Â&–æ6—ÂÂ–ÆöBÒ“°¢w&—FT§6öâ‡&W7öç6RÂ&W7VÇBç7FGW2Â&W7VÇBæ&öG’Â6÷'&VÆF–öä–B“°¢Ò6F6‚†W'&÷"’°¢–b†W'&÷"–ç7Fæ6Vöb‡GG–çWDW'&÷"’w&—FT§6öâ‡&W7öç6RÂW'&÷"ç7FGW2Â²W'&÷#¢W'&÷"æ6öFRÒÂ6÷'&VÆF–öä–B“°¢VÇ6Rw&—FT§6öâ‡&W7öç6RÂS2Â²W'&÷#¢&6FÆöu÷6W'f–6U÷Væf–Æ&ÆR"ÒÂ6÷'&VÆF–öä–B“°¢Ğ¢&WGW&ã°¢Ğ¢–b‡W&ÂçF†æÖRÓÒ"ö–çFW&æÂ÷cö66W72ÖFV6—6–öç2"’°¢w&—FT§6öâ‡&W7öç6RÂCBÂ²W'&÷#¢'&W6÷W&6Uöæ÷Eöf÷VæB"Ò“°¢&WGW&ã°¢Ğ¢–b‡&WVW7BæÖWF†öBÓÒ%õ5B"’°¢&W7öç6Rç6WD†VFW"‚&ÆÆ÷r"Â%õ5B"“°¢w&—FT§6öâ‡&W7öç6RÂCRÂ²W'&÷#¢&ÖWF†öEöæ÷EöÆÆ÷vVB"Ò“°¢&WGW&ã°¢Ğ ¢ÆWB6÷'&VÆF–öä–BÒ&æFöÕUT”B‚“°¢G'’°¢6öç7B²–ÆöBÂ&t&öG’ÒÒv—B&VD§6öâ‡&WVW7BÂÖ„&öG”'—FW2“°¢6öç7B&–æ6—ÂÒv—BWF†VçF–6FR‡&WVW7BÂ²&t&öG’Ò“°¢6÷'&VÆF–öä–BÒ&–æ6—Ãòæ6÷'&VÆF–öä–BÇÂ6÷'&VÆF–öä–C°¢6öç7B&W7VÇBÒv—BWfÇVFT66W75&WVW7D7–æ2‡²&W÷6—F÷'’Â&–æ6—ÂÂ–ÆöBÂ6W76–öäWF†÷&—G’Ò“°¢w&—FT§6öâ‡&W7öç6RÂ&W7VÇBç7FGW2Â&W7VÇBæ&öG’Â&W7VÇBæ6÷'&VÆF–öä–B“°¢Ò6F6‚†W'&÷"’°¢–b†W'&÷"–ç7Fæ6Vöb‡GG–çWDW'&÷"’°¢w&—FT§6öâ‡&W7öç6RÂW'&÷"ç7FGW2Â²W'&÷#¢W'&÷"æ6öFRÒÂ6÷'&VÆF–öä–B“°¢&WGW&ã°¢Ğ¢w&—FT§6öâ‡&W7öç6RÂSÂ²W'&÷#¢&–çFW&æÅöW'&÷""ÒÂ6÷'&VÆF–öä–B“°¢Ğ¢Ó°§Ğ