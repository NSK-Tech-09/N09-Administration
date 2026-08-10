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
d'exécution sera effectué depuis le site Node hébergé sur le même Server Cloud.

## Prochain jalon autorisé

1. créer le site Node `preprod-admin.nsktech.fr` ;
2. déposer le secret MariaDB dans les variables protégées Infomaniak ;
3. vérifier depuis ce site la connexion, les droits SQL et les déclencheurs ;
4. mettre en place puis tester sauvegarde et restauration ;
5. seulement ensuite, introduire les premières données de préproduction ;
6. raccorder OIDC et HTTPS après validation distincte.

La production et les applications existantes restent inchangées.
