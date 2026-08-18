# Déploiement de production

Cette procédure est la source de vérité de la livraison de N09 – Administration.
Elle applique `DEV-002`, `TST-003`, `REL-001` et `REL-002`.

## Architecture

Le workflow `deploy-production.yml` teste une fois le commit, installe les
dépendances verrouillées, crée une archive immuable et enregistre son SHA-256.
La cible contient uniquement :

```text
application/
  current -> releases/<commit complet>
  releases/<commit complet>/
  incoming/
  shared/.env
  shared/restart.sh
```

`shared/.env` est créé sur l'hébergement en mode `0600` et n'est ni transféré,
ni recopié dans les releases. La commande de lancement stable, exécutée depuis
`application/`, est :

```sh
set -a; . shared/.env; . current/release.env; set +a; exec node current/service-node/server.mjs
```

Le crochet `shared/restart.sh`, mode `0700`, contient exclusivement la commande
de redémarrage bornée à cette application. Le workflow refuse de déployer s'il
manque. La documentation Infomaniak ne publie actuellement aucune API de
redémarrage Node.js : ce crochet doit donc être validé sur l'hébergement avant
l'activation du workflow. Il ne doit contenir aucun secret.

## GitHub et compte Infomaniak

Créer un compte SSH/SFTP permanent dédié à **Administration**, limité à
l'hébergement `818413`. Ne pas employer ni modifier `g67ql3_nskportal-ci`, qui
reste réservé au portail. Le mot de passe est aléatoire, unique et conservé
uniquement dans le secret d'environnement GitHub `INFOMANIAK_DEPLOY_PASSWORD`.

L'environnement GitHub `production` contient les secrets
`INFOMANIAK_DEPLOY_HOST`, `INFOMANIAK_DEPLOY_PORT`,
`INFOMANIAK_DEPLOY_USERNAME`, `INFOMANIAK_DEPLOY_PASSWORD` et
`INFOMANIAK_SSH_HOST_KEY`, ainsi que les variables
`INFOMANIAK_DEPLOY_ROOT` et `PRODUCTION_HEALTH_URL`. La clé d'hôte doit être
relevée par un canal authentifié et épinglée ; `StrictHostKeyChecking` ne doit
jamais être désactivé.

## Activation et retour arrière

Après vérification de l'archive, le script crée la release en lecture seule,
remplace atomiquement `current`, redémarre puis exige pendant 30 secondes un
`/health` à l'état `ok` portant le commit complet attendu. À défaut, il restaure
le lien précédent, redémarre et met le job en échec. Les cinq dernières releases
sont conservées ; les archives de transfert sont supprimées dans tous les cas.

Pour une restauration volontaire, repointer `current` vers une release connue,
exécuter `shared/restart.sh`, puis vérifier `/health`. Une migration de données
incompatible exige sa propre sauvegarde et sa procédure de restauration avant
la livraison ; le workflow applicatif n'exécute aucune migration implicite.

## Rotation et diagnostic

Pour tourner le mot de passe, créer la nouvelle valeur côté Infomaniak, remplacer
le secret GitHub sans l'afficher, déclencher un déploiement contrôlé, puis révoquer
l'ancienne valeur. En cas d'échec, consulter d'abord l'étape GitHub fautive,
`readlink -f current`, la présence de `shared/.env` et les journaux Node du
Manager. Ne jamais afficher le contenu de `.env` ni lancer le serveur en mode
trace de shell.
