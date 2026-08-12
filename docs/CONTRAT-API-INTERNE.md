# Contrat de la première API interne

## Frontière d’authentification

L’adaptateur réseau doit fournir une application authentifiée avec une audience
validée et un identifiant de corrélation. Le noyau ne lit ni jeton ni secret :
leur validation appartient au composant OIDC placé devant cette frontière.

## Décision d’accès

L’opération `evaluate_access_request` accepte uniquement l’identité, l’application,
la permission, le périmètre et les conditions satisfaites. Une application ne
peut interroger que sa propre audience.

- absence d’authentification : `401` ;
- audience ou frontière applicative invalide : `403` ;
- entrée invalide ou champ inconnu : `400` ;
- identité ou application absente : réponse neutre `404` ;
- décision calculée : `200`, y compris lorsque l’accès est refusé.

Cette séparation évite de confondre un refus métier avec une panne du service.
Le transport HTTP conserve ces codes sans exposer de détail interne.

## Authentification technique du pilote

Le pilote `n09-suivi-taches` appelle cette frontière avec une identité technique
distincte de toute session humaine. Aucun cookie utilisateur n'est partagé entre
les sous-domaines.

Chaque requête porte les en-têtes suivants :

- `x-n09-client-id` : identifiant public du client technique ;
- `x-n09-timestamp` : date Unix en millisecondes sur 13 chiffres ;
- `x-n09-nonce` : UUID unique par requête ;
- `x-n09-signature` : HMAC-SHA256 en hexadécimal.

La signature couvre exactement la méthode, le chemin, la date, le nonce et le
SHA-256 du corps brut, séparés par des sauts de ligne. Le serveur refuse une date
écartée de plus de 30 secondes, un nonce rejoué, une audience différente ou une
signature invalide. Le transport TLS est obligatoire hors tests.

Le secret, d'au moins 32 caractères, reste hors du dépôt et doit pouvoir être
renouvelé indépendamment par environnement. Cette authentification de service ne
remplace pas le futur parcours central d'authentification de l'utilisateur.

## Publication du catalogue applicatif

`POST /internal/v1/application-access-catalogs` utilise la même preuve technique
signée. L’application authentifiée ne peut publier que pour son propre
`application_id`.

Le corps contient une version entière, les rôles, permissions, types de
périmètres et le contrat de provisionnement. Les champs inconnus, références
internes absentes, doublons et rôles actifs fondés sur un élément planifié sont
refusés.

- première publication valide : `201` ;
- répétition strictement identique : `200`, sans nouvel événement d’audit ;
- absence d’authentification : `401` ;
- tentative de publier pour une autre application : `403` ;
- application absente : `404` ;
- conflit de version, disparition d’un identifiant ou affectation active devenue
  ininterprétable : `409`.

Une publication réussie et nouvelle est enregistrée avec son empreinte SHA-256
et son événement d’audit dans la même transaction. Aucun secret, certificat ou
jeton ne fait partie du catalogue.

## Réception des événements de notification

`POST /internal/v1/notification-events` utilise la même preuve technique signée.
L'application authentifiée ne peut remettre que ses propres événements. Le
corps porte `contract_version: 1` et un tableau `events` non vide ; la limite
HTTP générale reste fixée à 64 Kio.

Chaque événement contient exactement `event_id`, `event_type`, `task_id`,
`site_id`, `actor_id`, `aggregate_id`, `payload` et `occurred_at`. La charge est
bornée, ne contient aucune coordonnée de destination ni secret et ne remplace
pas les préférences métier conservées par l'application émettrice.

- première remise valide : `202`, avec le nombre `accepted` ;
- répétition strictement identique : `200`, comptée dans `already_present` ;
- absence d'authentification : `401` ;
- audience étrangère : `403` ;
- application absente : `404` ;
- application inactive ou identifiant déjà associé à un autre contenu : `409`.

La réception crée un événement central `pending` et son audit dans une seule
transaction. La remise ne déclenche directement aucun courriel, message ou
notification push.
