"use client";

import { useMemo, useState } from "react";

type Provider = {
  key: string;
  name: string;
  mark: string;
  detail: string;
  status: "linked" | "available";
};

type AuditEntry = {
  time: string;
  action: string;
  detail: string;
  tone: "success" | "warning" | "neutral";
};

const initialProviders: Provider[] = [
  {
    key: "infomaniak",
    name: "Infomaniak",
    mark: "ik",
    detail: "Compte vérifié · camille@example.invalid",
    status: "linked",
  },
  {
    key: "email",
    name: "Lien par e-mail",
    mark: "@",
    detail: "camille@example.invalid",
    status: "available",
  },
  {
    key: "google",
    name: "Google",
    mark: "G",
    detail: "Compte personnel ou professionnel",
    status: "available",
  },
  {
    key: "microsoft",
    name: "Microsoft",
    mark: "M",
    detail: "Microsoft 365, Outlook ou compte personnel",
    status: "available",
  },
  {
    key: "github",
    name: "GitHub",
    mark: "GH",
    detail: "Compte développeur ou organisation",
    status: "available",
  },
  {
    key: "passkey",
    name: "Clé d’accès",
    mark: "◇",
    detail: "Cet appareil",
    status: "available",
  },
  {
    key: "phone",
    name: "Téléphone",
    mark: "+",
    detail: "Option de secours · jamais l’identité principale",
    status: "available",
  },
];

const initialAudit: AuditEntry[] = [
  {
    time: "10:42",
    action: "Connexion autorisée",
    detail: "Infomaniak → identité NSK-0001",
    tone: "success",
  },
  {
    time: "09:18",
    action: "Droit confirmé",
    detail: "N09 – Suivi des tâches · Administrateur",
    tone: "neutral",
  },
  {
    time: "Hier",
    action: "Identité rattachée",
    detail: "Compte Infomaniak ajouté à NSK-0001",
    tone: "neutral",
  },
];

export default function Home() {
  const [providers, setProviders] = useState(initialProviders);
  const [active, setActive] = useState(true);
  const [audit, setAudit] = useState(initialAudit);
  const [notice, setNotice] = useState(
    "Sélectionne un moyen de connexion pour simuler le parcours.",
  );
  const [scenario, setScenario] = useState<"known" | "unknown">("known");
  const [pendingProvider, setPendingProvider] = useState<Provider | null>(null);

  const linkedCount = useMemo(
    () => providers.filter((provider) => provider.status === "linked").length,
    [providers],
  );

  function addAudit(entry: Omit<AuditEntry, "time">) {
    setAudit((current) => [
      {
        ...entry,
        time: new Intl.DateTimeFormat("fr-FR", {
          hour: "2-digit",
          minute: "2-digit",
        }).format(new Date()),
      },
      ...current,
    ]);
  }

  function simulateLogin(provider: Provider) {
    if (provider.key === "infomaniak") {
      window.location.assign("/auth/infomaniak/start");
      return;
    }

    if (scenario === "unknown") {
      setPendingProvider(provider);
      setNotice(
        "Identité externe inconnue : aucun compte ni droit n’est créé automatiquement.",
      );
      addAudit({
        action: "Rattachement nécessaire",
        detail: `${provider.name} · identité externe inconnue`,
        tone: "warning",
      });
      return;
    }

    setPendingProvider(null);

    if (provider.status !== "linked") {
      setNotice(
        `${provider.name} n’est pas encore rattaché. Une preuve supplémentaire est nécessaire.`,
      );
      addAudit({
        action: "Rattachement nécessaire",
        detail: `${provider.name} → NSK-0001`,
        tone: "warning",
      });
      return;
    }

    if (!active) {
      setNotice(
        "Connexion refusée : le compte NSK est suspendu, quel que soit le fournisseur.",
      );
      addAudit({
        action: "Connexion refusée",
        detail: `${provider.name} · compte NSK suspendu`,
        tone: "warning",
      });
      return;
    }

    setNotice(
      `${provider.name} a prouvé l’identité. N09 – Administration autorise l’accès.`,
    );
    addAudit({
      action: "Connexion autorisée",
      detail: `${provider.name} → identité NSK-0001`,
      tone: "success",
    });
  }

  function linkProvider(provider: Provider) {
    setProviders((current) =>
      current.map((item) =>
        item.key === provider.key ? { ...item, status: "linked" } : item,
      ),
    );
    setNotice(
      `${provider.name} est maintenant une seconde porte vers le même compte NSK.`,
    );
    addAudit({
      action: "Identité rattachée",
      detail: `${provider.name} ajouté à NSK-0001`,
      tone: "success",
    });
  }

  function toggleAccount() {
    const next = !active;
    setActive(next);
    setNotice(
      next
        ? "Le compte NSK est réactivé : les moyens de connexion fonctionnent de nouveau."
        : "Le compte NSK est suspendu : toutes les portes d’entrée sont immédiatement bloquées.",
    );
    addAudit({
      action: next ? "Compte réactivé" : "Compte suspendu",
      detail: "Identité NSK-0001 · action administrative simulée",
      tone: next ? "success" : "warning",
    });
  }

  function submitAccessRequest() {
    if (!pendingProvider) return;
    setNotice(
      "Demande envoyée. L’identité externe est conservée sans aucun droit jusqu’à validation.",
    );
    addAudit({
      action: "Demande d’accès déposée",
      detail: `${pendingProvider.name} · aucune adresse obligatoire · aucun droit accordé`,
      tone: "neutral",
    });
    setPendingProvider(null);
  }

  function startSafeLinking() {
    if (!pendingProvider) return;
    setNotice(
      "N09 demande maintenant la preuve d’une session NSK existante avant tout rattachement.",
    );
    addAudit({
      action: "Vérification de rattachement",
      detail: `${pendingProvider.name} · seconde preuve demandée`,
      tone: "neutral",
    });
    setPendingProvider(null);
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">N09</span>
          <div>
            <strong>Administration</strong>
            <span>NSK Tech 09</span>
          </div>
        </div>

        <nav aria-label="Navigation principale">
          <p className="nav-label">POSTE DE CONTRÔLE</p>
          <a className="nav-item active" href="#identite">
            <span>◉</span> Identités
            <b>3</b>
          </a>
          <a className="nav-item" href="#applications">
            <span>▦</span> Applications
          </a>
          <a className="nav-item" href="#droits">
            <span>⌁</span> Droits d’accès
          </a>
          <a className="nav-item" href="#audit">
            <span>≡</span> Journal d’audit
          </a>
        </nav>

        <div className="sidebar-note">
          <span className="pulse" />
          <div>
            <strong>Mode démonstration</strong>
            <small>Aucune donnée réelle</small>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">IDENTITÉS / NSK-0001</p>
            <h1>Camille Martin</h1>
          </div>
          <div className="top-actions">
            <span className={`status ${active ? "status-active" : "status-paused"}`}>
              {active ? "Compte actif" : "Compte suspendu"}
            </span>
            <button className="ghost-button" onClick={toggleAccount}>
              {active ? "Suspendre" : "Réactiver"}
            </button>
          </div>
        </header>

        <div className="content-grid" id="identite">
          <section className="identity-card card">
            <div className="identity-heading">
              <div className="avatar">FT</div>
              <div>
                <h2>Identité NSK stable</h2>
                <p>La personne reste la même, quelle que soit sa porte d’entrée.</p>
              </div>
            </div>

            <dl className="identity-details">
              <div>
                <dt>Identifiant immuable</dt>
                <dd>NSK-0001 · 7f21…c98a</dd>
              </div>
              <div>
                <dt>Contact facultatif</dt>
                <dd>camille@example.invalid</dd>
              </div>
              <div>
                <dt>Moyens rattachés</dt>
                <dd>{linkedCount} actif{linkedCount > 1 ? "s" : ""}</dd>
              </div>
            </dl>

            <div className="principle">
              <span>✓</span>
              <p>
                <strong>Principe protégé</strong>
                Aucun e-mail ni numéro de téléphone n’est obligatoire. Ces
                coordonnées peuvent changer et ne suffisent jamais à fusionner
                deux comptes.
              </p>
            </div>
          </section>

          <section className="simulation-card card">
            <div className="card-title-row">
              <div>
                <p className="eyebrow">BAC À SABLE</p>
                <h2>Simuler une connexion</h2>
              </div>
              <span className="simulation-tag">1 CONNEXION RÉELLE</span>
            </div>

            <div className="scenario-switch" role="group" aria-label="Scénario">
              <button
                className={scenario === "known" ? "selected" : ""}
                onClick={() => {
                  setScenario("known");
                  setPendingProvider(null);
                }}
              >
                Camille connue
              </button>
              <button
                className={scenario === "unknown" ? "selected" : ""}
                onClick={() => {
                  setScenario("unknown");
                  setPendingProvider(null);
                }}
              >
                Visiteur inconnu
              </button>
            </div>

            <div className="provider-actions">
              {providers
                .filter((provider) =>
                  ["infomaniak", "google", "microsoft", "github"].includes(
                    provider.key,
                  ),
                )
                .map((provider) => (
                <button
                  className="login-button"
                  key={provider.key}
                  onClick={() => simulateLogin(provider)}
                >
                  <span className={`provider-mark provider-${provider.key}`}>
                    {provider.mark}
                  </span>
                  Continuer avec {provider.name}
                  {provider.key === "infomaniak" && (
                    <small className="real-badge">RÉEL</small>
                  )}
                  <span>→</span>
                </button>
                ))}
            </div>

            <div className="notice" aria-live="polite">
              <span>i</span>
              <p>{notice}</p>
            </div>
            {pendingProvider && (
              <div className="onboarding-panel">
                <p className="eyebrow">PREMIER ACCÈS</p>
                <h3>Cette identité n’est pas encore connue de NSK</h3>
                <p>
                  Aucune adresse n’est exigée. Que souhaites-tu faire avec ton
                  compte {pendingProvider.name} ?
                </p>
                <div>
                  <button onClick={submitAccessRequest}>Demander un accès</button>
                  <button className="secondary" onClick={startSafeLinking}>
                    Rattacher mon compte NSK
                  </button>
                </div>
              </div>
            )}
          </section>

          <section className="providers-card card">
            <div className="card-title-row">
              <div>
                <p className="eyebrow">PORTES D’ENTRÉE</p>
                <h2>Moyens de connexion</h2>
              </div>
              <span className="counter">{linkedCount} rattaché{linkedCount > 1 ? "s" : ""}</span>
            </div>

            <div className="provider-list">
              {providers.map((provider) => (
                <article className="provider-row" key={provider.key}>
                  <span className={`provider-mark provider-${provider.key}`}>
                    {provider.mark}
                  </span>
                  <div>
                    <h3>{provider.name}</h3>
                    <p>{provider.detail}</p>
                  </div>
                  {provider.status === "linked" ? (
                    <span className="linked-badge">Rattaché</span>
                  ) : (
                    <button className="link-button" onClick={() => linkProvider(provider)}>
                      Rattacher
                    </button>
                  )}
                </article>
              ))}
            </div>
            <p className="phone-warning">
              Le téléphone est accepté comme solution de secours pratique. Pour
              une action sensible, N09 demandera une passkey ou un autre moyen
              plus résistant au détournement de numéro.
            </p>
          </section>

          <section className="audit-card card" id="audit">
            <div className="card-title-row">
              <div>
                <p className="eyebrow">TRAÇABILITÉ</p>
                <h2>Dernières décisions</h2>
              </div>
              <span className="counter">En direct</span>
            </div>

            <div className="audit-list">
              {audit.slice(0, 6).map((entry, index) => (
                <article className="audit-row" key={`${entry.time}-${entry.action}-${index}`}>
                  <span className={`audit-dot ${entry.tone}`} />
                  <div>
                    <h3>{entry.action}</h3>
                    <p>{entry.detail}</p>
                  </div>
                  <time>{entry.time}</time>
                </article>
              ))}
            </div>
          </section>
        </div>
      </section>
    </main>
  );
}
