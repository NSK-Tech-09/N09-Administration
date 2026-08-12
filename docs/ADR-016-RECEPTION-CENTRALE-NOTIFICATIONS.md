# ADR-016 – Réception centrale des événements de notification

Statut : **implémentée et validée localement, non déployée**

Date : **12 août 2026**

## Contexte

N09 – Suivi des tâches produit désormais ses événements de notification dans
la même transaction MariaDB que la mutation métier. Cette boîte de sortie
empêche la perte silencieuse à la source, mais ne constitue pas encore une
remise au service central chargé de conserver les notifications et, plus tard,
d'activer leurs canaux.

La frontière décidée par ADR-001 reste inchangée : l'application émettrice
possède le sens de l'événement, ses objets et les préférences métier ;
Administration possède la réception durable et les futurs canaux de livraison.

## Décision

Administration expose `POST /internal/v1/notification-events`. La route utilise
la même identité technique HMAC que les décisions d'accès et la publication du
catalogue. La signature couvre la méthode, le chemin, l'horodatage, un nonce et
l'empreinte SHA-256 du corps brut. Sans preuve valide, l'entrée est refusée.

Le contrat version 1 accepte des lots de 1 à 100 événements issus exclusivement
de l'application authentifiée. Chaque événement contient seulement :

- son identifiant source stable et son type publié ;
- les identifiants de tâche, site, acteur éventuel et agrégat ;
- une charge JSON bornée à 16 Kio et un horodatage UTC canonique.

Les coordonnées de destination, contenus de commentaire, noms de fichier,
justifications, cookies, jetons, mots de passe et secrets sont interdits. Le
transport HTTP conserve en outre sa limite générale de 64 Kio par requête.

La clé centrale est le couple `source_application_id` et `source_event_id`.
Une remise strictement identique est idempotente et n'ajoute aucun audit. Le
même identifiant présenté avec un contenu différent provoque un conflit `409`
et annule le lot entier.

## Conservation et traitement

L'événement reçu et sa preuve d'audit `notification.event_received` sont écrits
dans la même transaction. La charge et son contexte source deviennent
immuables ; la suppression est interdite par déclencheur MariaDB.

Le cycle technique est explicite :

`pending` → `processing` → `processed`

Un échec place l'événement en `retry` avec un code borné et un délai
exponentiel, sans conserver le message d'erreur. Après cinq tentatives par
défaut, il passe en `quarantined`. Un bail expiré peut être repris par un autre
worker ; seul le détenteur du bail peut terminer ou reporter l'événement.

Ce lot ne fabrique aucun message utilisateur et n'appelle aucun canal externe.
Le futur traitement devra d'abord créer une notification interne durable, qui
restera le canal de référence conformément à `ARC-015`.

Le moteur de prise en charge n'est relié à aucun planificateur dans ce lot. Il
ne pourra être activé qu'avec un traitement métier lui-même idempotent ; aucun
événement reçu n'est donc prématurément déclaré traité.

## Retour arrière

Le schéma est additif. Une release antérieure ignore la table
`notification_events` ; la table et les événements déjà reçus ne doivent pas
être déposés lors d'un retour applicatif. La route peut rester fermée en
n'exécutant aucun publieur côté application.

La production, ses secrets et ses planificateurs historiques restent hors de ce
lot. Un déploiement en préproduction exigera une sauvegarde vérifiée, une
identité DDL bornée, l'application du schéma versionné, puis une recette signée
sur des événements sans effet externe.

## Vérification locale

- 129 tests Node.js réussissent dans N09 – Administration ;
- réception anonyme, mauvaise audience, champ inconnu et charge sensible refusés ;
- remise identique idempotente et conflit d'identité bloqué sans mutation partielle ;
- reprises, récupération de bail et quarantaine couvertes ;
- aucun secret ou détail d'erreur persistant dans le contrat ou le schéma.

## Référentiel appliqué

- `ARC-011` : identité applicative immuable et secrets renouvelables ;
- `ARC-013` : audit contextualisé sans donnée sensible ;
- `ARC-015` : notifications issues d'événements enregistrés, doublons et échecs gérés ;
- `DEV-002` : configuration et secrets séparés du code ;
- `TST-003` : scénarios normaux, refusés et dégradés reproductibles ;
- `REL-002` : migration additive, observable et réversible.
