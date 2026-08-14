# Lot 61 — Session centrale du portail Cloud

## Décision

Le portail public reste statique. N09 - Administration porte son courtier de
session afin de préserver une seule autorité d'identité et d'utiliser le Server
Cloud existant sans acheter un second environnement Node.js.

## Contrat de sécurité

- application centrale : `n09-portail` ;
- permission minimale : `portal:read` ;
- session applicative : audience `n09-portail`, durée d'inactivité et durée absolue bornées ;
- cookie du portail : contenu minimal scellé par AES-GCM ;
- aucune réutilisation des cookies Énergie, Tâches ou Administration ;
- origines web autorisées par liste exacte, sans joker ;
- URL de retour limitée aux origines et chemins publics attendus ;
- catalogue limité aux applications actives et aux affectations actives, valides dans le temps et sans condition en attente ;
- déconnexion opposable par révocation centrale confirmée.

## Points d'entrée

- `GET /portal/login` : entrée vers le parcours OIDC central ;
- `GET /portal/session` : projection minimale de l'identité et du catalogue autorisé ;
- `POST /portal/logout` : révocation et fermeture de la session du portail ;
- `GET /portal/account` : redirection vers la gestion centrale des sessions.

## Amorçage de production

La commande `npm run bootstrap:portal-production` crée ou met à jour de manière
idempotente l'application, la politique, le rôle et l'affectation du
propriétaire. Elle n'imprime aucun secret.

Variables attendues en production :

- `N09_PORTAL_SESSION_MODE=enforce` ;
- `N09_PORTAL_ORIGINS=https://nsktech.fr,https://www.nsktech.fr` ;
- les durées de session définies dans `.env.example` ;
- les secrets de chiffrement et de signature déjà gérés par l'environnement de production.

## Vérifications réalisées avant publication

- configuration et refus des valeurs dangereuses ;
- émission, expiration, altération et révocation de la session ;
- CORS exact et refus des origines étrangères ;
- filtrage du catalogue et permission minimale ;
- parcours HTTP de connexion, consultation, compte et déconnexion ;
- amorçage idempotent de la production ;
- suite Node complète : 276 contrôles réussis.

## Activation et retour arrière

Activer d'abord la release Administration, amorcer `n09-portail`, puis publier
le portail statique. Conserver la release Administration précédente et
l'ancien routage web pendant l'observation. En cas d'anomalie, remettre la
release précédente et le routage antérieur ; la messagerie reste hors périmètre.
