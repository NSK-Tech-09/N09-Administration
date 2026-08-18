# Déploiement de production

Cette procédure est la source de vérité de la livraison de N09 – Administration.
Elle applique `DEV-002`, `TST-003`, `REL-001` et `REL-002`.

## Architecture

Le workflow `deploy-production.yml` teste une fois le commit, installe les
dépendances verrouillées, crée une archive immuable et enregistre son SHA-256.
La cible contient uniquement :

```text
/srv/customer/
  current -> releases/<commit complet>
  releases/<commit complet>/
  incoming/
  shared/.env
  shared/deploy-transaction.sh
  shared/runner.sh
  shared/restart.sh
  shared/start-command
```

`shared/.env` est créé sur l'hébergement en mode `0600` et n'est ni transféré,
ni recopié dans les releases. À l'amorçage, copier sans l'afficher la
configuration active `current/service-node/.env`. La commande de lancement stable du Manager,
exécutée depuis le dossier du site, est :

```sh
N09_DEPLOY_ROOT=/srv/customer bash /srv/customer/shared/runner.sh
```

`runner.sh`, fourni dans `deploy/infomaniak-runner.sh`, lance la commande non
secrète de `shared/start-command`, charge la configuration partagée et surveille
un déclencheur. `restart.sh`, fourni dans `deploy/infomaniak-restart.sh`, change
ce déclencheur puis attend l'accusé de réception du lanceur. Les deux fichiers
sont en mode `0700`. Cette amorce unique remplace l'action manuelle du Manager ;
les déploiements suivants redémarrent ainsi l'application par SSH sans API
privée. Le workflow refuse de déployer si le crochet manque ou n'est pas validé.
La racine privée `/srv/customer` est volontaire : le compte SSH Node.js minimal
voit le dossier du site en lecture seule sur l'infrastructure Infomaniak.
`shared/start-command` contient
`cd "$N09_ACTIVE_RELEASE/service-node" && exec node server.mjs`. Le lanceur
préserve toujours le `PORT` imposé par le Manager après le chargement de `.env`.

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

Après vérification de l'archive, le script ouvre une transaction protégée, crée
la release en lecture seule et remplace atomiquement `current`. Le workflow
demande ensuite le redémarrage dans une connexion séparée : Infomaniak peut
fermer cette session pendant le redémarrage, ce qui est attendu. Le runner exige
alors pendant 60 secondes un `/health` à l'état `ok` portant le commit complet.
Il finalise la transaction seulement après cette preuve. À défaut, il restaure
le lien précédent, redémarre, vérifie le retour du service et met le job en
échec. Les cinq dernières releases sont conservées ; les archives et l'état de
transaction sont supprimés à la finalisation ou au retour arrière. Le script
transactionnel persistant rend ces opérations idempotentes après une coupure SSH.

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
