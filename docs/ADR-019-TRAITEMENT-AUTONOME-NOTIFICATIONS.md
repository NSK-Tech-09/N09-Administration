# ADR-019 — Traitement autonome et borné des notifications

Statut : **implémenté et validé localement, non déployé**

Date : **12 août 2026**

## Contexte

Les lots 39 et 40 ont validé la matérialisation interne puis son observation
gouvernée. Le consommateur restait toutefois une commande déclenchée à la main.
Cette dépendance humaine est acceptable pour une preuve, mais constitue une
dette d’exploitation dès lors que de nouveaux événements peuvent être remis à
Administration.

L’autonomie ne doit pas transformer le consommateur en service opaque, créer un
second système d’ordonnancement propriétaire ou ouvrir implicitement les canaux
externes.

## Décision

La commande `process:notifications` reste une exécution ponctuelle et sans état
local. Un planificateur standard peut l’invoquer périodiquement. Le mécanisme ne
dépend ni d’Infomaniak, ni d’un conteneur, ni d’un gestionnaire de processus
particulier : toute infrastructure capable d’exécuter une commande Node.js peut
le porter.

Chaque cycle exige simultanément :

- `N09_ALLOW_NOTIFICATION_PROCESSING=true` ;
- `N09_ENVIRONMENT=preprod` ;
- `N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY=false` ;
- une configuration MariaDB TLS valide ;
- le contrat signé de résolution vers N09 – Suivi des tâches.

La production reste donc fermée par construction. Sa future activation exigera
une décision et un lot distincts.

## Singleton distribué et reprise

Avant de réclamer un événement, le processus tente sans attente un verrou nommé
MariaDB. Si un cycle détient déjà ce verrou, l’invocation concurrente se termine
normalement avec l’état `skipped_overlap` et ne lit ni ne modifie la file.

Le verrou est attaché à une connexion dédiée et libéré dans tous les chemins de
sortie. Une disparition brutale de la connexion libère également le verrou côté
MariaDB. Les baux existants de `notification_events` restent la seconde ligne de
défense : un événement abandonné en cours de traitement redevient réclamable
après expiration du bail.

Cette combinaison évite les doublons tout en conservant la reprise. Elle ne
repose pas sur un fichier local, qui serait incorrect avec plusieurs instances.

## État opérationnel minimal

La table singleton `notification_processing_state` conserve uniquement le
dernier cycle : dates de début et de fin, succès ou échec, code d’erreur borné,
compteurs réclamés, traités, repris et mis en quarantaine, ainsi qu’une version.

Elle ne conserve ni identifiant de machine, ni événement, ni titre, ni message,
ni adresse, ni charge métier. Un cycle vide remplace l’état précédent au lieu de
créer une ligne indéfiniment ; aucune politique de purge supplémentaire n’est
donc nécessaire.

La console `/admin/notification-operations` présente cet état en lecture seule.
Elle ne permet ni de déclencher un cycle, ni de relancer un événement, ni de
modifier une préférence ou un canal.

## Canaux externes

Le lot n’ajoute aucun expéditeur et ne lit aucun secret SMTP, push, Telegram,
SMS ou WhatsApp. Les livraisons demandées continuent d’être enregistrées avec
l’état `blocked`. La garde externe indépendante empêche le simple démarrage du
consommateur interne de devenir une autorisation d’envoi.

## Validation locale

- **155 tests Node.js** réussissent ;
- refus hors préproduction et refus si la garde externe n’est pas explicitement
  fermée ;
- un seul cycle sous verrou et abandon propre d’un chevauchement ;
- libération du verrou après succès comme après panne ;
- code d’erreur borné sans message interne ;
- état singleton sans charge métier ;
- console toujours protégée par `administration:notifications:read` et dépourvue
  d’action de traitement.

## Déploiement prévu

Le déploiement en préproduction devra respecter cet ordre :

1. sauvegarder et vérifier la base Administration ;
2. appliquer uniquement la table additive `notification_processing_state` ;
3. déployer la release immuable et exécuter les tests sur Infomaniak ;
4. fixer les trois gardes avec les valeurs décidées ci-dessus ;
5. exécuter un cycle manuel vide et vérifier son état dans la console ;
6. créer un ordonnancement périodique sans chevauchement ;
7. observer au moins deux cycles et confirmer que toutes les livraisons externes
   restent bloquées ;
8. conserver la release précédente et la sauvegarde pour le retour arrière.

La fréquence d’ordonnancement relève de l’exploitation et peut changer sans
modifier le contrat applicatif. Une minute est une valeur initiale acceptable en
préproduction, sous réserve d’observer la durée réelle des cycles.

## Références

- `ADR-016-RECEPTION-CENTRALE-NOTIFICATIONS.md`
- `ADR-017-MATERIALISATION-CENTRE-NOTIFICATIONS.md`
- `ADR-018-OBSERVABILITE-NOTIFICATIONS.md`
- `ARC-013`
- `ARC-015`
- `TST-001`
