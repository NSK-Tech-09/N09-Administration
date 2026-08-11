# Contrat d’identité et d’accès – version 0.3

## Identité

| Champ | Règle |
|---|---|
| `identity_id` | UUID immuable, jamais réutilisé |
| `email` | coordonnée modifiable, normalisée et vérifiable |
| `display_name` | nom d’affichage commun |
| `status` | `invited`, `active`, `suspended`, `disabled`, `archived`, `deleted` |
| `identity_type` | `human` ou `service`, avec propriétaire pour un service |

## Application

Chaque application possède un identifiant immuable, des responsables métier et
technique, un état, des adresses autorisées et une politique d’inscription :
`closed`, `invitation` ou `approval`. Le mode ouvert n’existe pas.

Elle publie un catalogue versionné de rôles, permissions et types de périmètres
avec des identifiants techniques stables et des libellés compréhensibles.

Chaque version est un instantané immuable. Une nouvelle version ne peut ni
réutiliser un numéro avec un autre contenu, ni faire disparaître silencieusement
un identifiant déjà publié. Les éléments non encore applicables sont déclarés
`planned` ; les éléments retirés progressivement sont conservés en
`deprecated`. Une affectation active doit rester interprétable.

Le catalogue publie également le contrat de provisionnement : clé de liaison,
création automatique éventuelle, usage autorisé ou interdit du courriel et
prérequis que l’application doit confirmer. Ce contrat ne déplace aucune donnée
métier dans Administration et ne crée aucun accès.

## Affectation

Une affectation centrale suit le modèle :

`Sujet + Application + Rôle + Périmètre + Conditions`

Elle porte aussi un état, une période de validité, un motif, le décideur, une
version et, le cas échéant, le groupe dont elle est héritée.

## Décision

L’accès est accordé uniquement lorsque l’identité et l’application sont actives
et qu’au moins une affectation active correspond exactement à la permission, au
périmètre, aux conditions et à la période demandés. Toute absence ou ambiguïté
est refusée par défaut. Le contrôle final est exécuté côté serveur par
l’application destinataire. Un rôle administratif central ne contourne jamais
un droit métier absent.

## N09 – Suivi des tâches

Le catalogue version 2 conserve `tasks-pilot-reader` en état `deprecated` pour
la seule continuité de l'affectation globale du pilote et active les rôles
bornés `tasks-reader` et `tasks-writer` sur le périmètre `site`. Aucun nouvel
octroi pilote global n'est donc possible. `tasks-administrator` et
`tasks:admin` restent planifiés. Une activation de catalogue n'est jamais un
octroi.

Le profil `application_users`, son rôle métier et ses appartenances de sites
restent dans Suivi des tâches. Chaque affectation centrale porte les trois
prérequis publiés comme conditions ; l'application ne les présente comme
satisfaits qu'après les avoir revérifiés côté serveur pour la requête et le site
concernés. La liaison se fait exclusivement par `identity_id` : aucun
rapprochement automatique par courriel et aucune création implicite ne sont
autorisés.
