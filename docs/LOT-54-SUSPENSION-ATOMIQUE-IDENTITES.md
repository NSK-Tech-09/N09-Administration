# Lot 54 — suspension atomique des identités

Statut : **déployé et recetté en préproduction**

Date : **13 août 2026**

## Objet

Fermer la dernière dette explicitement laissée par le lot 53 et par l’ADR-020 :
la suspension gouvernée d’une identité NSK doit révoquer toutes ses sessions
applicatives encore actives dans la même transaction.

Une suspension n’est ni une suppression, ni un archivage. L’identité, ses
affectations et toute son histoire demeurent conservées. Les contrôles d’accès
existants refusent immédiatement une identité dont l’état n’est plus `active`.

## Frontière de gouvernance

Le catalogue Administration passe en version 5 et ajoute uniquement :

- la permission `administration:identities:suspend` ;
- le rôle global `identity-suspension-administrator` ;
- une console distincte `/admin/identities`.

Ce pouvoir ne découle d’aucun rôle technique générique. Son attribution reste
un amorçage ponctuel, explicite, audité et limité à une base de préproduction.
La personne opératrice ne peut pas suspendre sa propre identité depuis cette
console : cette décision exige une gouvernance séparée afin d’éviter un
verrouillage solitaire de l’administration.

## Opération atomique

Après contrôle de la permission, de l’état attendu `active`, d’une cible scellée,
du jeton CSRF et d’une justification de 20 à 500 caractères, le service :

1. verrouille l’identité cible ;
2. verrouille dans un ordre stable toutes ses sessions actives observées ;
3. vérifie leurs versions et leur appartenance à l’identité ;
4. passe l’identité à `suspended` ;
5. révoque chaque session avec le même acteur, le même motif et le même
   identifiant de corrélation ;
6. inscrit l’événement `identity.suspended`, puis les événements
   `application_session.revoked`, dans la chaîne d’audit centrale ;
7. valide l’ensemble en une seule transaction.

Une session expirée n’est pas artificiellement révoquée. Si l’identité ou une
session change concurremment, toute l’opération est annulée : aucune suspension
partielle ne subsiste et aucun succès trompeur n’est présenté.

## Minimisation et interface

La console affiche le nom, l’adresse de contact et le nombre de sessions actives.
Elle n’expose aucun cookie, secret, empreinte, adresse réseau ni identifiant
technique d’identité ou de session. La cible réelle voyage uniquement dans un
jeton chiffré, authentifié, lié à l’opérateur et valable dix minutes.

## Validation locale

La validation complète réussit :

- **236 tests Node.js** ;
- **63 tests Python** ;
- contrôle du comportement MariaDB transactionnel ;
- refus sans permission, hors périmètre, en auto-suspension, avec CSRF invalide,
  jeton altéré, justification insuffisante ou état concurrent ;
- preuve de rollback complet lorsqu’une version de session devient périmée ;
- chaîne d’audit toujours valide et sans identifiant complet de session.

## Exécution réelle en préproduction

Le **13 août 2026**, le commit canonique
`551db4b4725ca61d591d8e1376924421c3ded024` a été déployé dans la release
immuable `releases/551db4b`. L’archive complète porte l’empreinte SHA-256
`2cccb8152043ff9d7231a9c94a3fc45c3a53e2b874aef265d526b8f3127b5181`.
Les **190 fichiers** de source ont été contrôlés par manifeste, puis le dossier
a été figé en lecture seule. Les dépendances ont été réinstallées avec
`pnpm 11.16.0` depuis le verrou officiel et `mysql2 3.23.2`.

La sauvegarde préalable est conservée sous
`/srv/customer/backups/preprod-admin/lot54-pre-identity-suspension-20260813T185145Z.sql.gz`.
Elle pèse **31 283 octets**, passe le contrôle gzip, contient la fin d’export et
porte l’empreinte SHA-256
`6d325682b4da14bc25cf0c24497d0d7138f5bc10d71f503edf4a23fef548a01c`.
Comme au lot 53, l’export utilise `--skip-triggers` sans élargir les privilèges
du compte d’exécution ; les déclencheurs restent versionnés dans la release.

La release a réussi **236 tests Node.js** et **63 tests Python** sur Infomaniak.
Le catalogue Administration **version 5** a été publié avec l’empreinte
`fe48460d21d7a6239c23d96ac0875999759c9c5e10bbffd9913627c89a45115e`,
puis le rôle `identity-suspension-administrator` a été attribué à l’identité
principale par l’amorçage borné à la préproduction. La chaîne d’audit était
valide après chacune de ces opérations.

Le premier redémarrage a été refusé par le garde-fou parce que le marqueur de
provenance avait été placé un niveau trop haut. Aucun service incomplet n’a donc
démarré. Le marqueur a été remis dans la release scellée, tous les contrôles ont
été rejoués, puis Infomaniak a démarré normalement `releases/551db4b`. La santé
publique répond `200` avec `{"status":"ok"}`, la route non authentifiée
`/admin/identities` répond `401`, le worker interne termine ses cycles avec
succès et les canaux externes demeurent fermés.

La recette a utilisé l’identité non privilégiée **Fred TRAVERS — Recette**
(`travers.fred.09@gmail.com`). Une session N09 – Suivi des tâches éphémère et
auditée a été créée uniquement pour éprouver la fermeture atomique. La console
a affiché une session active, puis a suspendu l’identité avec une justification
explicite. Le contrôle final confirme : identité `suspended`, **zéro session
active**, **une session révoquée**, événements `identity.suspended` et
`application_session.revoked` partageant la même corrélation, chaîne d’audit
valide. Une ancienne session déjà expirée est restée non révoquée, conformément
à la règle de non-réécriture de l’histoire.

L’identité principale est restée active avec ses deux sessions et la console a
continué à refuser son auto-suspension. `releases/0e01ac1` ainsi que la
sauvegarde ci-dessus constituent le retour arrière immédiat. Aucune modification
n’a touché la production ni N09 – Énergie.
