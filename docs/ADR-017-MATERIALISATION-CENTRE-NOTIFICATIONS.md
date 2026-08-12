# ADR-017 — Matérialisation centrale et centre de notifications

Statut : **implémenté et validé localement, non déployé**

Date : **12 août 2026**

## Décision

N09 – Administration devient propriétaire du centre de notifications interne et
de l’état des livraisons. L’application émettrice reste propriétaire du sens de
l’événement, des destinataires métier et des préférences associées.

La prise en charge d’un événement suit donc trois étapes distinctes :

1. Administration réclame à l’application émettrice une résolution métier signée ;
2. Administration matérialise une notification interne par identité centrale ;
3. les canaux externes demandés sont enregistrés mais restent bloqués tant qu’un
   lot dédié n’a pas ouvert, sécurisé et recetté chaque canal.

Cette séparation applique `ARC-015`, `ERG-018`, `ADR-001` et `ADR-013` sans
transférer les secrets de canal ni les règles métier dans la mauvaise application.

## Contrat inverse signé

Administration appelle `POST /internal/v1/notification-intents` sur N09 – Suivi
des tâches avec une identité technique propre à ce sens de communication. Le
secret est distinct de celui utilisé par l’application pour publier ses
événements. La signature HMAC lie méthode, chemin, date, nonce et empreinte du
corps ; le rejeu et les requêtes périmées sont refusés.

La réponse contient uniquement l’identité centrale du destinataire, une catégorie,
une importance, un titre et un message autonomes et bornés, un contexte applicatif
structuré et les canaux souhaités selon les préférences métier. Elle ne contient ni
adresse électronique, numéro de téléphone, identifiant Telegram, URL libre, contenu
de commentaire, secret ou preuve de session.

## Persistance et idempotence

Trois tables additives portent la décision :

- `notification_resolutions` conserve le résultat de politique, y compris quand
  aucun destinataire n’est retenu ;
- `notifications` porte le centre interne, l’état lu/non lu et un archivage futur
  séparé de l’audit ;
- `notification_external_deliveries` conserve les canaux demandés.

L’identifiant d’une notification est déterministe à partir de l’application, de
l’événement et de l’identité destinataire. Une reprise après interruption retrouve
la même résolution ; une dérive de contenu est refusée. La matérialisation et son
événement d’audit sont écrits dans une transaction unique.

La résolution et le contenu d’une notification sont immuables. Seuls les états
de lecture et d’archivage peuvent évoluer ; la suppression reste interdite tant
qu’une politique de conservation distincte n’a pas été décidée.

Toute identité destinataire doit exister et être active dans le registre central.
Une identité absente ou suspendue provoque une reprise contrôlée, jamais une
livraison vers une coordonnée de substitution.

## Canaux externes fermés

Le canal `in_app` est matérialisé immédiatement. Chaque demande `email`, `push`,
`telegram`, `sms` ou `whatsapp` devient une ligne `blocked` avec le motif
`channel_not_enabled`. Ce lot ne contient aucun expéditeur SMTP, VAPID, Telegram,
SMS ou WhatsApp et n’accède à aucun secret de canal.

La commande de traitement est elle-même fermée par
`N09_ALLOW_NOTIFICATION_PROCESSING=false`. Elle ne doit être activée que pour une
prise en charge contrôlée, puis immédiatement refermée.

## Centre utilisateur

Une session NSK authentifiée peut consulter uniquement ses notifications sur
`/notifications`, voir le compteur de non-lus, la source, la date et le contexte,
marquer une notification ou toutes ses notifications comme lues. Chaque écriture
exige le jeton CSRF de la session. Lire ne supprime ni la notification ni l’audit.

Les deux événements actuellement en attente sont informatifs ; ils ne portent
aucune action sensible. Les futures notifications d’action devront conduire vers
l’application centrale ou métier pour y refaire les contrôles de session et de
droit, jamais exécuter la décision depuis un courriel.

## Validation locale

- **140 tests Node.js Administration** réussissent ;
- validation de la signature inverse, de la confidentialité du contrat, de
  l’idempotence et du blocage de tous les canaux externes ;
- validation du centre personnel, du cloisonnement par identité et du CSRF ;
- validation du schéma additif et de l’absence de secret dans les tables ;
- `git diff --check` réussit sur le périmètre du lot.

## Déploiement contrôlé à venir

Le déploiement devra être réalisé dans cet ordre : sauvegarde vérifiée de la base
Administration, création du secret directionnel, application du schéma additif,
déploiement des deux services, vérification du contrat signé, activation ponctuelle
du consommateur, contrôle des résolutions et notifications, puis fermeture de la
garde. Le nombre de livraisons externes non bloquées devra rester strictement nul.

Une recette humaine vérifiera ensuite le centre, le compteur et la lecture. La
production historique reste inchangée et toute promotion exige une décision
distincte.
