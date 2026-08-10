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
le port interne `3000` et exécute le transport HTTP versionné de N09 –
Administration. Le domaine est propagé, le certificat est sécurisé et le site
est en ligne. Aucune application de l'écosystème n'y est encore raccordée.

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

## Sauvegarde et restauration vérifiées

Infomaniak expose une sauvegarde de la base datée du **10 août 2026 à
08:15:54**. Elle est sélectionnable et téléchargeable depuis le Manager.

Un export logique complet a aussi été restauré dans la base isolée temporaire
`6p7h3x_n09_admin_restore`. Le premier essai a confirmé que le compte
d'exécution ne peut pas exporter les déclencheurs, conformément à ses droits
minimaux. Un compte éphémère a donc reçu les seuls privilèges nécessaires pour
l'exercice.

L'export MariaDB contenait le `DEFINER` technique d'origine des déclencheurs. La
restauration isolée l'a refusé sans privilège global ; la clause a été retirée
de la copie avant un second essai réussi. La sauvegarde testée faisait **8 706
octets** et portait l'empreinte SHA-256
`8539254002facd335179e3020ad58027c592480cc2c8a3633a5df9ab87295143`.

La base restaurée contenait cinq tables, deux déclencheurs, une tête de chaîne
d'audit et aucune donnée utilisateur. Le code retour final était `0`. La base
isolée, le compte éphémère, son secret et le fichier SQL temporaire ont ensuite
été supprimés. Les deux bases et les deux comptes permanents sont les seuls
éléments restants.

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

## Transport et données synthétiques vérifiés

Les PR **#14** et **#15** ont été fusionnées avant déploiement. La version active
porte le commit `72de3040441edd0add88d4d0d74ae67c10b33de1`. Elle est installée
dans un dossier de version distinct ; la version précédente reste disponible
pour un retour arrière.

Les dépendances ont été installées avec pnpm **11.16.0** et le lockfile validé.
Les **45 tests Node** réussissent également sur l'environnement Infomaniak.

Le frontal managé exige une écoute sur l'interface du conteneur. Cette exception
est bornée par `N09_TRUSTED_REVERSE_PROXY=true`, sans ouverture d'un port
applicatif brut. Les contrôles réels confirment :

- `GET https://preprod-admin.nsktech.fr/health` : `200` et `{"status":"ok"}` ;
- absence de cache et protection `nosniff` sur la réponse ;
- `POST /internal/v1/access-decisions` sans OIDC : `401` et
  `authentication_required` ;
- secret MariaDB toujours hors dépôt et fichier d'environnement toujours en
  permissions `600`.

Le premier amorçage a créé exactement une identité, une application et une
affectation synthétiques. Deux exécutions suivantes n'ont rien recréé
(`created: []`). Chaque passage a confirmé une chaîne d'audit valide. L'adresse
utilisée appartient au domaine réservé `example.invalid` ; aucune donnée
utilisateur réelle n'a été introduite.

## Prochain jalon autorisé

Les jalons 1 à 6 (site Node, secret protégé, connexion, droits SQL, sauvegarde,
restauration, données synthétiques et transport HTTPS fermé) sont terminés. Le
prochain jalon autorisé est désormais :

1. raccorder et valider l'adaptateur OIDC ;
2. autoriser une première application pilote après validation distincte ;
3. autoriser des données utilisateur seulement après validation fonctionnelle
   et décision explicite.

La production et les applications existantes restent inchangées.
