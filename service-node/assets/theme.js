const choices = new Set(["system", "light", "gray", "dark"]);
const selector = document.querySelector("#nsk-theme");
const stored = localStorage.getItem("nsk-theme");
const requested = new URLSearchParams(window.location.search).get("theme");
const initial = choices.has(requested) ? requested : choices.has(stored) ? stored : "system";

document.documentElement.dataset.theme = initial;
if (choices.has(requested)) localStorage.setItem("nsk-theme", requested);
if (selector) {
  selector.value = initial;
  selector.addEventListener("change", () => {
    const value = choices.has(selector.value) ? selector.value : "system";
    document.documentElement.dataset.theme = value;
    localStorage.setItem("nsk-theme", value);
  });
}

document.querySelector("#nsk-quick-access")?.addEventListener("change", (event) => {
  const destination = event.currentTarget.value;
  if (destination.startsWith("/")) window.location.assign(destination);
});

const sessionActions = document.querySelector(".header-actions");
const accountAction = sessionActions?.querySelector('a[href="/account"]');
const logoutAction = sessionActions?.querySelector('form[action="/auth/logout"]');
const currentPath = window.location.pathname;
const protectedAuthenticatedPage = currentPath === "/account" || currentPath.startsWith("/account/") ||
  currentPath === "/notifications" || currentPath.startsWith("/notifications/") ||
  currentPath === "/admin" || currentPath.startsWith("/admin/");
let loginAction = null;
let userCopy = null;
let previousAuthenticationState = null;

if (sessionActions && accountAction && logoutAction) {
  const requestedReturn = new URLSearchParams(window.location.search).get("return_to");
  const returnTo = window.location.pathname.startsWith("/account") && requestedReturn
    ? requestedReturn
    : window.location.href;
  const accountUrl = new URL("/account", window.location.origin);
  accountUrl.searchParams.set("return_to", new URL(returnTo, window.location.origin).href);
  accountUrl.searchParams.set("theme", initial);
  accountAction.href = accountUrl.toString();
  accountAction.textContent = "Mon compte";
  userCopy = document.createElement("span");
  userCopy.className = "header-user-copy";
  userCopy.style.display = "grid";
  userCopy.style.minWidth = "145px";
  userCopy.innerHTML = "<strong>Utilisateur NSK Tech 09</strong><small>Session active</small>";
  sessionActions.prepend(userCopy);
  Object.assign(sessionActions.style, {
    minHeight: "62px", padding: "8px 10px", border: "1px solid var(--line)",
    borderRadius: "8px", background: "var(--muted-bg)",
  });
  sessionActions.style.visibility = "hidden";
  loginAction = document.createElement("a");
  loginAction.className = "button secondary";
  loginAction.textContent = "Se connecter";
  sessionActions.append(loginAction);
}

function displayAuthenticationState(authenticated, displayName = "Utilisateur NSK Tech 09") {
  if (!sessionActions || !accountAction || !logoutAction || !loginAction) return;
  if (userCopy) {
    userCopy.hidden = !authenticated;
    const name = userCopy.querySelector("strong");
    if (name) name.textContent = displayName;
  }
  accountAction.hidden = !authenticated;
  logoutAction.hidden = !authenticated;
  loginAction.hidden = authenticated || protectedAuthenticatedPage;
  sessionActions.style.visibility = "";
}

async function refreshAuthenticationState() {
  if (!sessionActions) return;
  let authenticated = false;
  let displayName = "Utilisateur NSK Tech 09";
  let authenticationUnavailable = false;
  try {
    const response = await fetch("/auth/session", { credentials: "include", cache: "no-store" });
    if (!response.ok && response.status !== 401) throw new Error("session_check_unavailable");
    const state = response.ok ? await response.json() : { authenticated: false };
    authenticated = state.authenticated === true;
    displayName = state.display_name || displayName;
  } catch {
    authenticationUnavailable = true;
  }

  const returnTo = window.location.pathname.startsWith("/auth/")
    ? "/"
    : `${window.location.pathname}${window.location.search}${window.location.hash}`;
  const loginHref = `/auth/login?return_to=${encodeURIComponent(returnTo)}`;
  loginAction.href = loginHref;

  if (authenticationUnavailable) {
    displayAuthenticationState(protectedAuthenticatedPage || previousAuthenticationState === true, displayName);
    return;
  }
  if (!authenticated && protectedAuthenticatedPage) {
    window.location.replace(loginHref);
    return;
  }
  if (previousAuthenticationState === true && !authenticated) {
    window.location.reload();
    return;
  }

  displayAuthenticationState(authenticated, displayName);
  previousAuthenticationState = authenticated;
}

if (sessionActions) {
  void refreshAuthenticationState();
  const refresh = () => { void refreshAuthenticationState(); };
  const refreshWhenVisible = () => {
    if (document.visibilityState === "visible") refresh();
  };
  window.setInterval(refresh, 60_000);
  window.addEventListener("focus", refresh);
  window.addEventListener("pageshow", refresh);
  document.addEventListener("visibilitychange", refreshWhenVisible);
}
