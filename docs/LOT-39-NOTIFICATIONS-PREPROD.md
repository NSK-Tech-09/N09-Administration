# Lot 39 — Centre de notifications en préproduction

Date de validation : 2026-08-12

## État synthétique

- `N09-Administration` actif sur la release `e9ca31f`.
- `N09-Suivi-des-tâches` actif sur la release `c0edcdd` (commit complet `c0edcddd894518e691bb1c9904471fb9bbaa3f4f`).
- Les deux applications répondent correctement après redémarrage explicite dans le Manager Infomaniak.
- L'endpoint interne de collecte refuse un appel anonyme avec le statut HTTP `401`.
- La liaison Administration → Suivi des tâches utilise un secret distinct, présent dans les deux fichiers d'environnement protégés en mode `600`.
- Le traitement permanent reste désactivé : `N09_ALLOW_NOTIFICATION_PROCESSING=false`.
- Les canaux externes restent bloqués par conception.

## Sauvegarde et intégrité

- Sauvegarde SQL avant migration : `/srv/customer/backups/preprod-admin/lot39-pre-migration-20260812T165941Z.sql`.
- Taille : `87488` octets.
- SHA-256 : `f134ad7ac2a0520e07802a26a50d9564674289e0d600ecc8b6e798893118153d`.
- Archive Administration : `n09-admin-e9ca31f.tar.gz`.
- SHA-256 de l'archive Administration : `3012bc14cd0517bc6c3f4fe3af42e0f16541869a5ebb24efae09e290f864f454`.
- Archive Suivi des tâches : `n09-tasks-c0edcdd.tar.gz`.
- SHA-256 de l'archive Suivi des tâches : `2a6bfad1760d47d609f620b908a6797fdeb3d193d7dd78e5c231e6caf7ae064d`.
- Sauvegarde des définitions de déclencheurs avant réattribution : `/srv/customer/backups/preprod-admin/lot39-triggers-before-definer-cleanup.sql`.
- SHA-256 de cette sauvegarde : `85c97eac2d22a320737e2a7bfd5551226afb89404cecbdb05b202901770a6510`.

## Schéma MariaDB

Les tables suivantes sont présentes dans `6p7h3x_n09_admin_preprod` :

- `notification_events` ;
- `notification_resolutions` ;
- `notifications` ;
- `notification_external_deliveries`.

La collision de nom MariaDB entre la clé unique et la contrainte de canal a été corrigée :

- clé unique : `notification_external_delivery_channel` ;
- contrainte de valeur : `notification_external_delivery_channel_value`.

Les tests Administration passent à `140/140` et les tests Suivi des tâches à `200/200`.

## Validation fonctionnelle

Le consommateur a été exécuté ponctuellement avec l'autorisation de traitement activée uniquement pour ce processus. La commande normale a ensuite été restaurée et l'application redémarrée.

Résultat après une première puis une seconde exécution identique :

| Indicateur | Valeur |
| --- | ---: |
| Événements traités | 2 |
| Résolutions persistées | 2 |
| Notifications internes créées | 0 |
| Livraisons externes non bloquées | 0 |

La seconde exécution n'a créé aucun doublon. L'absence de notification interne est cohérente avec l'absence de destinataire éligible pour ces deux événements historiques.

## Droits MariaDB

Le compte durable de migrations `6p7h3x_n09ddl` dispose désormais, sur la base Administration, des droits `Lecture` et `Administration`, sans droit `Écriture`. Ce profil est identique à celui déjà appliqué à la base Suivi des tâches et permet aux déclencheurs dont il est propriétaire de lire les valeurs `OLD/NEW` sans transformer ce compte en compte applicatif.

## Clôture des propriétaires de déclencheurs

Le mot de passe du compte durable de migrations `6p7h3x_n09ddl` a été régénéré. Il est conservé hors dépôt dans `/srv/customer/private-secrets/n09-mariadb-ddl.env` : le fichier est en mode `600` et son répertoire n'accorde aucun accès groupe ou tiers.

Les six déclencheurs initialement créés depuis une session phpMyAdmin temporaire ont été recréés à l'identique sous le propriétaire durable `6p7h3x_n09ddl@%` :

- `audit_events_no_delete` ;
- `audit_events_no_update` ;
- `notifications_no_delete` ;
- `notifications_payload_immutable` ;
- `notification_resolutions_no_delete` ;
- `notification_resolutions_no_update`.

Les deux déclencheurs de `notification_events` appartenaient déjà à ce compte. Le contrôle final de `information_schema.TRIGGERS` confirme donc :

- `TRIGGER_TOTAL=8` ;
- `DURABLE_OWNER_TOTAL=8` ;
- aucun propriétaire temporaire restant.

Un essai de modification de `notification_resolutions` a été refusé comme prévu par le déclencheur d'immutabilité. Les données n'ont pas été modifiées par ce contrôle.

Le lot 39 est techniquement clos en préproduction.

## Retour arrière

- Administration : restaurer la commande de démarrage vers `releases/c5835a4` et la sauvegarde SQL ci-dessus si un retour de schéma est nécessaire.
- Suivi des tâches : restaurer la commande de démarrage vers `releases/19c5533`.
- Les anciennes releases restent présentes ; aucune suppression n'a été réalisée pendant le lot.

