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
