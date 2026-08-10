# État de la préproduction Infomaniak

Date du constat : **10 août 2026**  
Périmètre : **N09 – Administration**

## État confirmé

- MariaDB **10.11.18** sur `6p7h3x.myd.infomaniak.com:3306` ;
- base dédiée : `6p7h3x_n09_admin_preprod` ;
- compte d'exécution : `6p7h3x_n09arun` ;
- droits du compte d'exécution : **lecture et écriture uniquement** sur la base
  Administration, sans administration et sans accès à la base Suivi des tâches ;
- compte temporaire de migration supprimé après installation du schéma ;
- aucun secret versionné ou conservé dans un fichier de travail.

Le site `preprod-admin.nsktech.fr` est créé sur l'hébergement dédié **N09 -
Coeur et Administration** du Server Cloud. Il utilise Node.js **24**, écoute sur
le port interne `3000` et reste limité à un projet d'accueil neutre : aucun
transport HTTP métier ni aucune application de l'écosystème n'y est encore
raccordé. Le domaine est propagé, le certificat est indiqué comme sécurisé et
le site est en ligne au niveau de l'hébergement ; aucun processus applicatif
Node n'est toutefois lancé tant qu'un point d'entrée validé n'est pas déployé.

Le secret MariaDB actif est stocké uniquement dans le fichier d'environnement
du site, hors dépôt, avec les permissions `600`. Un premier secret généré a été
affiché dans la console à la suite d'un chemin SSH incorrect ; il a été
immédiatement révoqué avant utilisation, l'historique de session a été effacé et
un nouveau secret non affiché a été installé.

Le schéma versionné `service-node/mariadb/schema.sql` a été appliqué avec succès.
Les cinq tables suivantes existent :

- `identities` ;
- `applications` ;
- `access_assignments` ;
- `audit_events` ;
- `audit_chain_head`.

Les déclencheurs `audit_events_no_update` et `audit_events_no_delete` sont
installés. La tête de chaîne initiale existe, sans événement métier.

## Limites constatées

Le tableau de bord de l'hébergement affiche actuellement **« Aucune
sauvegarde »**. La base ne doit donc recevoir aucune donnée utilisateur réelle
avant qu'une sauvegarde et une restauration aient été exécutées puis vérifiées.

Une tentative de connexion depuis l'environnement local a expiré. MariaDB n'est
donc pas considérée comme accessible depuis Internet. Le test du compte
d'exécution a été effectué depuis le site Node hébergé sur le même Server Cloud.
Il confirme :

- la connexion interne à MariaDB et la présence des cinq tables (`RC=0`) ;
- l'écriture autorisée dans une transaction puis son rollback effectif
  (`1` pendant la transaction, `0` après rollback) ;
- le refus d'une mise à jour et d'une suppression dans `audit_events` par les
  deux déclencheurs d'immutabilité (`SQLSTATE 45000`) ;
- l'absence finale de toute donnée de test (`0`).

## Prochain jalon autorisé

Les jalons 1 à 3 (site Node, secret protégé, connexion et droits SQL) sont
terminés. Le prochain jalon autorisé est désormais :

1. mettre en place puis tester sauvegarde et restauration ;
2. seulement ensuite, introduire les premières données de préproduction ;
3. déployer le transport HTTP après sa validation isolée ;
4. raccorder OIDC et HTTPS après validation distincte.

La production et les applications existantes restent inchangées.
