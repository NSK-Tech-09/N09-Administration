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
const accountAction = sessionActions?.querySelector('a[href="/account/sessions"]');
const logoutAction = sessionActions?.querySelector('form[action="/auth/logout"]');
let loginAction = null;
let previousAuthenticationState = null;

if (sessionActions && accountAction && logoutAction) {
  sessionActions.style.visibility = "hidden";
  loginAction = document.createElement("a");
  loginAction.className = "button secondary";
  loginAction.textContent = "Se connecter";
  sessionActions.append(loginAction);
}

function displayAuthenticationState(authenticated) {
  if (!sessionActions || !accountAction || !logoutAction || !loginAction) return;
  accountAction.hidden = !authenticated;
  logoutAction.hidden = !authenticated;
  loginAction.hidden = authenticated;
  sessionActions.style.visibility = "";
}

async function refreshAuthenticationState() {
  if (!sessionActions) return;
  let authenticated = false;
  try {
    const response = await fetch("/auth/session", { credentials: "include", cache: "no-store" });
    authenticated = response.ok && (await response.json()).authenticated === true;
  } catch {
    authenticated = false;
  }

  if (previousAuthenticationState === true && !authenticated) {
    window.location.reload();
    return;
  }

  const returnTo = window.location.pathname.startsWith("/auth/")
    ? "/"
    : `${window.location.pathname}${window.location.search}${window.location.hash}`;
  loginAction.href = `/auth/login?return_to=${encodeURIComponent(returnTo)}`;
  displayAuthenticationState(authenticated);
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
