# ADR-001 – Séparer identité, affectations et données métier

Statut : **Accepté**  
Date : **9 août 2026**

## Contexte

N09 – Suivi des tâches contient actuellement des comptes locaux, des sessions,
un rôle global, des affectations par site et la configuration des canaux de
messagerie. N09 – Énergie assure temporairement l’identité partagée.

## Décision

N09 – Administration devient la source de vérité pour les identités, leur cycle
de vie, le registre et les catalogues applicatifs, les affectations de rôles dans
un périmètre et sous conditions, les délégations, les décisions et l’audit.

Chaque application reste source de vérité pour ses objets métier, publie son
catalogue de rôles, permissions et types de périmètres, puis contrôle côté
serveur la décision effective. Administration ne réinterprète pas les données
métier.

Les canaux de livraison des notifications seront centralisés. La signification
des événements et les préférences métier restent dans l’application émettrice.

## Conséquences

- un compte seul ne donne aucun accès ;
- toute affectation est explicite, datée, justifiée et révocable ;
- le super-administrateur technique n’obtient aucun accès métier implicite ;
- la révocation est propagée rapidement et reste contrôlable ;
- aucune application ne lit directement la base d’Administration ;
- la migration est progressive, comparée et réversible avant suppression de la
  seconde source locale.
