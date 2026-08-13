# Lot 42 — Preuve du refus d’écriture applicatif en préproduction

Statut : **validé techniquement en préproduction, publication documentaire à effectuer**

Date : **13 août 2026**

## Objet

Le jalon laissé ouvert après le déploiement des octrois gouvernés exigeait de
prouver qu’une commande de N09 — Suivi des tâches est arrêtée avant toute
mutation lorsqu’aucun octroi `tasks:write` ne couvre son site exact.

La preuve devait rester sans dette : aucune tâche factice, aucune affectation
temporaire et aucune modification d’un droit réel.

## Scénario retenu

L’identité NSK active de Frédéric TRAVERS est reconnue dans N09 — Suivi des
tâches. L’interface authentifiée confirme simultanément :

- lecture autorisée sur le site **ADAPEI 09** ;
- écriture non accordée sur ce même site ;
- absence de toute commande de création dans l’interface pour ce périmètre.

La preuve serveur utilise ensuite le client d’autorisation centrale de la
release réellement active de Suivi des tâches, avec les mêmes paramètres que
la commande HTTP :

- application : `n09-suivi-taches` ;
- permission : `tasks:write` ;
- type de périmètre : `site` ;
- site : `site_47043b1d08e7` (ADAPEI 09) ;
- conditions présentées : `application-user-profile`, `application-role` et
  `site-membership`.

## Résultat

Administration refuse la décision avec le motif borné `scope_mismatch`.
L’appel au modèle d’écriture reste à `false` : aucune transaction de commande
n’est ouverte après le refus central.

Les compteurs MariaDB ont été lus avant et après la décision :

| Objet durable | Avant | Après |
|---|---:|---:|
| Tâches | 165 | 165 |
| Activités de tâches | 1 006 | 1 006 |
| Reçus de commandes | 15 | 15 |
| Événements de notification | 2 | 2 |

Le constat final est donc `mutation: false`. La preuve a été produite le
13 août 2026 à `02:16:23.388Z` par la release Suivi des tâches
`c0edcddd894518e691bb1c9904471fb9bbaa3f4f`.

## Garanties conservées

- aucun droit n’a été accordé, révoqué ou réactivé pour la recette ;
- aucune tâche, activité, notification ou clé d’idempotence n’a été créée ;
- aucune donnée personnelle ni aucun secret n’a été ajouté aux journaux ;
- la production historique reste inchangée ;
- les doubles contrôles central et local restent en place ;
- le refus par défaut et le périmètre exact sont confirmés en conditions
  réelles de préproduction.

## Conclusion

Le jalon « commande refusée sans `tasks:write` » est clos. L’interface évite
l’action et le serveur confirme indépendamment que l’autorisation centrale
arrête la commande avant toute mutation. Aucun objet de recette n’est à
nettoyer.

## Références

- `ADR-009-APPLICATION-PILOTE-SUIVI-TACHES.md`
- `ADR-015-OCTROIS-APPLICATIFS-GOUVERNES.md`
- `ETAT-PREPROD-INFOMANIAK.md`
- N09 — Suivi des tâches : `LOT-25-COMMANDES-TACHES-GOUVERNEES.md`
- N09 — Suivi des tâches : `LOT-26-CAPACITES-AUTHENTIFIEES.md`
