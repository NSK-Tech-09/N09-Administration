# Lot 47 — Opposabilité des sessions dans N09 – Suivi des tâches

Statut : **implémenté et validé localement, non publié et non déployé**

Date : **13 août 2026**

## Objet

Ce lot prépare la troisième étape de `ADR-020` : rendre le registre central de
sessions opposable dans N09 – Suivi des tâches, application pilote. Il ne rend
pas encore les sessions d'Administration opposables et ne modifie aucun
environnement.

## Contrat central

L'échange serveur à serveur du code de connexion peut désormais créer une
session centrale propre à `n09-suivi-taches`. La réponse remet une seule fois la
référence opaque, le secret aléatoire et les deux échéances. Le secret brut ne
rejoint ni MariaDB, ni l'audit, ni une URL, ni un journal.

Chaque décision d'accès signée peut présenter cette preuve. Lorsque le mode
`enforce` est activé pour l'application pilote, Administration contrôle avant
les droits :

1. l'existence de la session ;
2. l'identité et l'application liées ;
3. l'empreinte du secret en temps constant ;
4. la révocation ;
5. l'expiration après inactivité et l'expiration absolue.

Une absence, une divergence, une expiration, une révocation ou une
indisponibilité ferme l'accès. Une activité valide est consolidée au plus toutes
les cinq minutes. Une expiration constatée est fermée et auditée une seule fois.

## Activation en deux temps

`N09_TASKS_SESSION_MODE` accepte trois valeurs :

- `disabled`, valeur par défaut, préserve intégralement le contrat courant ;
- `issue`, crée la preuve lors des nouvelles connexions sans la rendre
  opposable ;
- `enforce`, exige la preuve centrale sur chaque décision de l'application
  pilote.

`issue` et `enforce` sont refusés hors `N09_ENVIRONMENT=preprod`. La bascule
préparée est : déployer les deux services en mode `issue`, ouvrir une nouvelle
session réelle, vérifier sa présence et son audit, puis passer à `enforce` sans
fermer la possibilité de revenir immédiatement à `issue` ou `disabled`.

## Déconnexion

La route interne signée de révocation n'accepte que l'application propriétaire,
l'identité et la référence de session. Elle ne reçoit pas le secret. Une
application ne peut pas révoquer une session d'une autre application ou d'une
autre identité.

Suivi des tâches inscrit d'abord la référence dans une liste de refus locale
persistante, puis demande la révocation centrale. En cas d'indisponibilité, le
cookie est effacé, l'interface annonce que la fermeture centrale reste en cours
et le rejeu borné reprend jusqu'à confirmation. La file ne conserve ni secret,
ni cookie, ni empreinte.

## Validation locale

- **189 tests Node.js Administration** réussissent ;
- émission préparatoire et mode opposable fermés hors préproduction ;
- absence, secret erroné, contexte différent, expiration et révocation refusés ;
- consolidation d'activité bornée ;
- expiration et révocation auditables sans référence ni empreinte ;
- route de révocation limitée à l'application technique propriétaire ;
- contrat historique inchangé lorsque le mode reste désactivé.

La matrice complémentaire côté application est consignée dans le lot 40 de
N09 – Suivi des tâches.

## Frontière et retour arrière

Aucune migration n'est appliquée, aucune release n'est construite et aucune
configuration distante n'est modifiée par ce lot local. La production reste
inchangée.

Le retour applicatif consiste à remettre `N09_TASKS_SESSION_MODE=issue` ou
`disabled` et à restaurer la release précédente. Les sessions et audits centraux
déjà créés sont conservés comme preuves ; ils ne sont jamais supprimés pendant
un retour arrière.

## Références

- `ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`
- `LOT-46-ACTIVATION-OBSERVATION-SESSIONS-PREPROD.md`
- `ARC-008`
- `ARC-010`
- `ARC-012`
- `ARC-013`
- `ARC-016`
- `TST-001`
