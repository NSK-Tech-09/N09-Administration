# Lot 53 — Révocation opérateur des sessions

Statut : **implémenté et validé localement ; aucune mutation de préproduction effectuée**

Date : **13 août 2026**

## Objectif

Achever l’étape 7 de l’ADR-020 en donnant à un opérateur explicitement habilité
la capacité de consulter les sessions actives de l’écosystème et d’en révoquer
une, sans créer de super-administrateur implicite et sans exposer les secrets du
registre.

## Pouvoir séparé

Le catalogue de N09 – Administration passe en version 4 et ajoute :

- la permission `administration:sessions:revoke` ;
- le rôle `session-revocation-administrator` ;
- le seul type de périmètre `global` pour cette première mise en œuvre.

Ce périmètre global n’est pas implicite : il correspond à une affectation
centrale précise, active et auditée. Une affectation portant une permission
voisine ou un autre périmètre est refusée. L’interface générale de décision des
accès ne peut toujours pas attribuer un pouvoir de gouvernance de
N09 – Administration ; l’amorçage initial conserve donc une procédure dédiée,
bornée à une base dont le nom se termine par `_preprod` et activée par
`N09_ALLOW_OPERATOR_SESSION_BOOTSTRAP=true`. Elle refuse également toute
affectation tant que le rôle et la permission ne sont pas actifs dans le
catalogue Administration version 4 effectivement publié.

## Console opérateur

La route `GET /admin/sessions` présente uniquement les sessions encore actives :

- personne et adresse de contact centrale ;
- application et contexte compréhensible ;
- création, dernière activité, expiration d’inactivité et échéance absolue ;
- signalement de la session opérateur courante.

La page ne contient ni secret, ni empreinte, ni cookie, ni adresse réseau, ni
identifiant technique de session. La cible transmise au navigateur est enfermée
pendant dix minutes dans un jeton chiffré et authentifié qui lie l’opérateur,
l’identité cible, la session et sa version.

`POST /admin/sessions/revoke` exige simultanément :

- une session NSK centrale active ;
- la permission dédiée dans le périmètre global ;
- la preuve CSRF de la session ;
- un jeton cible intact, non expiré et émis pour le même opérateur ;
- une justification comprise entre 20 et 500 caractères ;
- une session cible encore active à la version attendue.

La session opérateur courante n’est jamais révocable depuis cette console. Elle
reste fermable depuis l’espace personnel, qui applique la déconnexion ordinaire.
Les autres sessions du même opérateur restent révocables comme celles des autres
personnes.

## Mutation et audit

La révocation et son événement `application_session.revoked` restent atomiques
dans le dépôt transactionnel existant. L’événement conserve l’opérateur réel,
l’identité concernée, l’application, le motif et la corrélation, mais exclut la
référence et l’empreinte de session. Un conflit de version ou une cible déjà
fermée ne produit aucun succès fictif et ne laisse aucune mutation partielle.

## Déploiement contrôlé en préproduction

Le passage en préproduction devra respecter cet ordre :

1. consigner le commit canonique et vérifier une sauvegarde restaurable ;
2. publier le catalogue Administration version 4 avec la commande contrôlée
   existante ;
3. déployer une release immuable et vérifier santé, connexion et pages déjà en
   service ;
4. prouver que `/admin/sessions` répond `403` à une identité sans le nouveau
   pouvoir ;
5. exécuter l’amorçage dédié avec une justification humaine explicite ;
6. vérifier la console sans effectuer de révocation non planifiée ;
7. créer ou choisir une session de recette distincte, la révoquer, puis prouver
   son refus au contrôle serveur suivant ;
8. vérifier la chaîne d’audit et consigner les résultats réels.

Le retour arrière applicatif restaure la release précédente. Le catalogue
version 4 reste additif et peut demeurer publié ; l’affectation opérateur peut
être révoquée par la procédure de gouvernance prévue, sans supprimer son histoire.

## Exécution réelle en préproduction

Le **13 août 2026**, la PR **#61** a été fusionnée dans `main` avec le commit
canonique `0e01ac1a4756704f7ea2fd41031912e67491df10`. La release immuable
`releases/0e01ac1` a été construite depuis l'archive complète de ce commit,
dont l'empreinte SHA-256 est
`bc7a51dfa2973d2cbb55b96fd30926968f8aa3cd9e24641b8e69cf836aec99be`.
Les **183 fichiers** du manifeste ont été vérifiés avant le gel de la release.

La sauvegarde préalable est conservée sous
`/srv/customer/backups/preprod-admin/lot53-pre-operator-session-revocation-20260813T173642Z.sql.gz`.
Elle pèse **28 412 octets**, passe le test gzip, contient la fin d'export du
**13 août 2026 à 17:36:56 UTC** et porte l'empreinte SHA-256
`0b56debebfe68f2f3304b5a8031fda46f9ba4313a732bceee67cc64c619b8892`.
Le compte d'exécution a correctement refusé `SHOW CREATE TRIGGER` faute du
privilège `TRIGGER` ; l'export a donc été produit avec `--skip-triggers`, sans
élargir les droits. Une restauration complète associe cet export au schéma et
aux déclencheurs versionnés dans la release.

La release complète a réussi **223 tests Node.js** et **63 tests Python** sur
Infomaniak. Les marqueurs de source, tests, sauvegarde, catalogue, dépendances
et renouvellement de session ont été contrôlés avant le démarrage, puis le
dossier a été figé en lecture seule. Une première reconstruction incrémentale
a été refusée par le manifeste et supprimée avant activation. Le premier
redémarrage de diagnostic a ensuite rencontré un port temporairement occupé ;
le processus de diagnostic a été fermé et le démarrage géré par Infomaniak a
confirmé `service_started`. Les contrôles local et public de `/health` ont
répondu `200` avec `{"status":"ok"}`.

Le catalogue Administration **version 4** a été publié avec l'empreinte
`4598c3412bba808c149abf9bf83241c26037fdf61ce560320accd315c1c94f9a`.
Avant tout octroi, `/admin/sessions` a affiché **Accès refusé** pour l'identité
principale, prouvant l'absence de droit implicite. L'amorçage borné à la
préproduction a ensuite créé l'affectation
`session-revocation-administrator` de Fred TRAVERS, avec la justification du
lot 53 et une chaîne d'audit valide.

La console a recensé la session Administration courante et une session Tâches
distincte. Elle n'a proposé aucune action sur la session opérateur courante. La
session Tâches nouvellement créée a été révoquée avec une justification de
recette ; la requête suivante sur N09 – Suivi des tâches a redirigé vers la page
de connexion. Une nouvelle authentification SSO saine a ensuite restauré
l'accès normal à Tâches.

Le registre affiche désormais le catalogue v4, le rôle et la permission
`administration:sessions:revoke`, ainsi que **sept affectations actives**. La
lecture finale de l'audit montre `application_session.revoked` en succès, puis
la création de la nouvelle session Tâches ; `verifyAuditChain()` renvoie
`true`. La page d'exploitation des notifications reste opérationnelle, son
dernier cycle interne est réussi et tous les canaux externes demeurent bloqués.

Les releases `releases/16399df` et `releases/dbf951a`, ainsi que la sauvegarde,
restent disponibles pour retour arrière. Les fichiers temporaires de transfert
ont été supprimés. Aucune mutation n'a été effectuée en production ni dans
N09 – Énergie.

## Validation automatisée

Les tests dédiés prouvent :

- permission exacte, identité active et périmètre global ;
- absence de droit implicite avec une permission voisine ou un périmètre voisin ;
- présentation des seules sessions actives sans secret ;
- révocation d’une session d’une autre identité avec acteur et motif exacts ;
- refus de la session courante, d’une cible hors identité et d’une version
  périmée ;
- refus de la route sans permission, avec CSRF invalide, jeton altéré ou jeton
  émis pour un autre opérateur ;
- amorçage préproduction séparé, auditée et idempotent ;
- évolution séquentielle et idempotente du catalogue jusqu’à la version 4.

Au contrôle local du lot, **223 tests Node et 63 tests Python réussissent**.

## Hors périmètre

- aucune révocation automatique lors de la suspension d’une identité dans ce lot ;
- aucun périmètre partiel par site, groupe ou application ;
- aucune gestion des facteurs, mots de passe ou moyens de récupération ;
- aucune mutation de production ou de préproduction sans recette séparée.

La révocation automatique lors d’une suspension reste une opération gouvernée à
concevoir avec son atomicité propre ; elle ne doit pas être simulée par la console
unitaire.
