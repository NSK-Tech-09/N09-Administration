# ADR-013 – Révocation centrale des accès

Statut : **proposée pour la préproduction**

## Contexte

Le registre central sait déjà identifier une personne, enregistrer les
applications et évaluer leurs affectations. Son premier écran d'accès est
volontairement limité à la consultation. La prochaine capacité doit permettre
une décision humaine réelle sans créer une seconde source de vérité pour les
rôles métier, les sites ou les préférences de notification.

Accorder un nouvel accès suppose encore un catalogue de rôles publié par
l'application et, pour N09 – Suivi des tâches, un profil applicatif relié à
l'identité NSK. Une affectation centrale créée sans ces prérequis serait un
droit inutilisable ou incohérent.

## Décision

La première mutation proposée par N09 – Administration est uniquement la
révocation d'une affectation centrale active.

Elle exige :

- la permission exacte `administration:access:decide`, distincte de la simple
  consultation `administration:access:read` ;
- une session NSK authentifiée et une preuve CSRF ;
- l'identifiant immuable et la version affichée de l'affectation ;
- une justification de 20 à 500 caractères ;
- une identité opératrice active ;
- un événement `assignment.revoked` écrit dans la même transaction que le
  passage à l'état `revoked` et l'incrément de version.

Le pouvoir `administration:access:decide` lui-même n'est jamais révocable
depuis cet écran général. Son attribution, son passage de relais et son retrait
relèvent d'une procédure dédiée, afin qu'aucune concurrence entre deux requêtes
ne puisse supprimer le dernier décideur.

## Frontières de responsabilité

Administration décide si une identité peut accéder à une application et porte
la preuve durable de cette décision. L'application conserve ses rôles métier,
ses périmètres locaux et ses préférences fonctionnelles.

Les secrets SMTP, Telegram ou VAPID ne sont ni des droits utilisateurs ni des
données à copier dans ce registre. Ils relèvent d'un futur service de
notifications ; les préférences d'un utilisateur restent dans l'application
qui sait les interpréter.

## Conséquences

- une révocation centrale devient immédiatement opposable aux applications ;
- aucun octroi arbitraire n'est possible depuis l'interface ;
- une soumission périmée échoue sans écraser une décision plus récente ;
- la continuité du pouvoir de décision est protégée ;
- l'étape suivante pourra formaliser le catalogue de rôles et le provisionnement
  explicite des profils applicatifs avant d'ouvrir les octrois.
