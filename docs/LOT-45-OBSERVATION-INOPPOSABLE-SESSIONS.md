# Lot 45 — Observation inopposable des sessions Administration

Statut : **implémenté et validé localement, non publié et non déployé**

Date : **13 août 2026**

## Objet

Ce lot met en œuvre la deuxième étape du déploiement progressif défini par
`ADR-020`. Les nouvelles connexions rattachées de N09 – Administration peuvent
désormais créer une session dans le registre central et comparer son état lors
des requêtes suivantes, sans lui donner encore aucun pouvoir de décision.

Le cookie OIDC actuel demeure la seule preuve opposable. Une session centrale
absente, divergente, expirée, révoquée ou momentanément indisponible ne refuse
donc aucun accès dans ce lot.

## Activation fermée par défaut

Le mode est contrôlé par `N09_SESSION_SHADOW_MODE` :

- `disabled`, valeur par défaut, n'effectue aucune lecture ni écriture ;
- `observe`, seule autre valeur admise, est refusée hors de
  `N09_ENVIRONMENT=preprod`.

Il n'existe volontairement aucune valeur `enforce`. L'opposabilité fera l'objet
d'un lot, d'une recette et d'une décision de déploiement distincts.

Les durées proposées restent celles de l'ADR : trente minutes d'inactivité,
huit heures absolues et une consolidation de l'activité au plus toutes les cinq
minutes. Elles sont explicites et validées au démarrage.

## Création observée

Après un retour OIDC Infomaniak valide, seule une identité NSK déjà rattachée et
active peut être inscrite. Le registre reçoit l'empreinte du secret et l'audit
de création dans la même transaction. Le secret brut et la référence sont
enfermés dans le cookie chiffré, authentifié, `HttpOnly`, `Secure` et
`SameSite=Lax` déjà utilisé par Administration.

Une identité encore en attente de rattachement n'est pas inscrite. Si la
création centrale échoue, le cookie courant est néanmoins émis sans preuve
centrale : la panne est mesurée, mais n'interrompt pas la connexion actuelle.

## Comparaison en arrière-plan

Chaque ouverture valide du cookie actuel déclenche une comparaison asynchrone :

- présence de la session dans le registre ;
- concordance de l'identité, de l'application et du secret ;
- absence de révocation ;
- validité des échéances absolue et d'inactivité ;
- consolidation bornée de la dernière activité.

Le résultat n'est jamais attendu pour répondre à la requête et n'est jamais
utilisé par le contrôle d'accès. Les anciens cookies, qui ne portent aucune
preuve centrale, sont comptés comme `not_enrolled` et restent valides selon les
règles antérieures.

## Mesures sans données sensibles

Le composant conserve des compteurs agrégés de créations, observations,
divergences, indisponibilités et consolidations. Il émet des événements JSON
bornés avec seulement l'opération, le résultat et un code de cause prédéfini.

Sont exclus des compteurs et journaux : identité, adresse, référence de session,
secret brut, empreinte, cookie et message d'erreur interne. Une défaillance du
journal lui-même est également absorbée.

## Déconnexion et limites volontaires

La déconnexion actuelle efface encore seulement le cookie. Elle ne révoque pas
la session observée : rendre cette mutation opposable avant le contrôle des
requêtes créerait un état incohérent. Les sessions d'observation non réutilisées
expirent donc par inactivité.

Ce lot ne branche pas encore :

- N09 – Suivi des tâches ;
- la révocation à la déconnexion ;
- la fermeture d'accès sur divergence ou indisponibilité ;
- l'espace personnel et la révocation distante ;
- la révocation opérateur.

## Validation locale

La suite complète réussit avec **179 tests Node** et **63 tests Python**, sans
échec. Elle prouve notamment :

- l'inertie totale du mode désactivé ;
- le refus du mode observation hors préproduction ;
- la création centrale et l'enfermement de la preuve dans le cookie chiffré ;
- la consolidation bornée de l'activité ;
- la détection d'un secret divergent sans refus d'accès ;
- la continuité d'accès lorsque l'observation échoue ;
- l'absence de donnée fournie ou sensible dans les journaux ;
- la compatibilité des anciens cookies non inscrits.

## Absence d'impact externe

- aucune migration n'a été appliquée à la préproduction ;
- `N09_SESSION_SHADOW_MODE` n'a été activé dans aucun environnement ;
- aucune session réelle n'a été créée ;
- aucune release n'a été construite ou redémarrée ;
- la production demeure inchangée.

## Étape suivante

Publier ce lot puis préparer son activation contrôlée en préproduction :
sauvegarde vérifiée, application du schéma additif déjà fusionné, configuration
explicite du mode `observe`, nouvelle connexion de recette et lecture des
mesures. L'opposabilité restera interdite pendant cette phase d'observation.

## Références

- `ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`
- `LOT-43-SOCLE-REGISTRE-SESSIONS.md`
- `LOT-44-PERSISTANCE-AUDIT-SESSIONS.md`
- `ARC-010`
- `ARC-013`
- `TST-001`
