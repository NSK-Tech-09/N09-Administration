# Lot 54 — suspension atomique des identités

Statut : **implémenté et validé localement ; activation distante séparée**

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

## Déploiement ultérieur

L’activation en préproduction formera une opération séparée : sauvegarde vérifiée,
publication du catalogue v5, affectation gouvernée de la permission, release
immuable, recette avec une identité de démonstration non privilégiée et retour
arrière conservé. La production et N09 – Énergie ne sont pas modifiées par ce lot.
