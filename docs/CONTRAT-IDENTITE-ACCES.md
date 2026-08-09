# Contrat d’identité et d’accès – version 0.2

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

L’application publiera ses rôles `reader` et `writer`, ses permissions et le type
de périmètre `site`. Après migration vérifiée, leurs affectations ne resteront
pas une seconde source de vérité locale.
