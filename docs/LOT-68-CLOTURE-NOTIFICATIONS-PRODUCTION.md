# Lot 68 — Clôture des notifications en production

Date de recette : 16 août 2026
Statut : **déployé, activé et recetté en production**

## Objectif

Fermer la dernière dette d'exploitation de la chaîne de notifications entre
N09 – Suivi des tâches et N09 – Administration : propriétaires MariaDB
durables, traitement autonome, livraison courriel réelle et preuves de
non-duplication.

## Propriétaire des déclencheurs MariaDB

Les huit déclencheurs de la base Administration sont désormais détenus par le
compte technique dédié `g67ql3_n09trig@%` :

- `notification_resolutions_no_update` ;
- `notification_resolutions_no_delete` ;
- `notifications_no_delete` ;
- `notifications_payload_immutable` ;
- `audit_events_no_update` ;
- `audit_events_no_delete` ;
- `notification_events_no_delete` ;
- `notification_events_payload_immutable`.

Ce compte n'est ni un compte humain ni le compte de l'application. Il dispose
uniquement de la lecture nécessaire et des droits d'administration de
structure indispensables aux déclencheurs. Il ne dispose d'aucun droit
d'écriture métier. Son secret reste exclusivement dans le gestionnaire
Infomaniak et n'est présent ni dans GitHub, ni dans une release, ni dans les
journaux.

Les anciens propriétaires `g67ql3_temp_1@%` et le compte applicatif ne
définissent plus aucun déclencheur. Toute évolution future d'un déclencheur
doit être appliquée par le compte technique dédié, puis contrôlée dans
`information_schema.TRIGGERS`. Le serveur applicatif conserve seulement ses
droits métier ordinaires.

## Recette réelle

L'événement borné `event_recipe_email_20260816_1712`, émis par
`n09-suivi-taches`, a été :

1. reçu une seule fois par Administration ;
2. traité en une tentative, sans erreur ni quarantaine ;
3. matérialisé en une notification interne pour l'identité centrale de Fred
   TRAVERS ;
4. livré une seule fois par courriel à `f.travers@nsktech.fr` ;
5. conservé avec le statut `delivered`, une tentative et l'horodatage
   `2026-08-16T18:01:42.070Z`.

Le canal push reste volontairement `blocked` avec le motif
`channel_not_enabled`. Aucun autre destinataire et aucun autre canal n'ont été
ouverts pendant la recette.

## Configuration active

- `N09_ALLOW_NOTIFICATION_PROCESSING=true` ;
- `N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY=true` ;
- la date plancher de livraison externe reste en place afin d'exclure les
  anciennes lignes ;
- la boucle interne exécute le consommateur puis le livreur courriel sans
  chevauchement ;
- `/health` répond `200` après redémarrage du service de production.

## Retour arrière

En cas d'incident, remettre
`N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY=false`, redémarrer Administration
et conserver les événements, notifications et livraisons en base. Ne pas
supprimer les lignes : leur état idempotent permet une reprise contrôlée sans
nouvel événement source.

Le compte propriétaire des déclencheurs doit être conservé tant que les huit
déclencheurs existent. Sa suppression rendrait les protections MariaDB
inopérantes et n'est donc jamais une opération de retour arrière.
