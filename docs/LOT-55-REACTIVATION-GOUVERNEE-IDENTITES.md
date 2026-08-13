# Lot 55 — réactivation gouvernée des identités

Statut : **implémenté et validé localement — non déployé**

Date : **13 août 2026**

## Objet

Compléter le cycle de vie ouvert par le lot 54 sans réintroduire les risques que
la suspension atomique a supprimés. Une identité `suspended` peut revenir à
l’état `active` uniquement après une nouvelle décision humaine explicite et
auditée. Cette transition ne restaure jamais une ancienne session.

La réactivation n’accorde aucun droit nouveau : les affectations conservées sont
à nouveau évaluées par les règles centrales au prochain parcours
d’authentification. Une nouvelle connexion reste donc obligatoire.

## Séparation des responsabilités

Le catalogue Administration passe en version 6 et ajoute exactement :

- la permission `administration:identities:reactivate` ;
- le rôle global `identity-reactivation-administrator` ;
- l’action de réactivation dans la console existante `/admin/identities`.

Le pouvoir de réactivation est distinct du pouvoir de suspension
`administration:identities:suspend`. Posséder l’un ne confère jamais l’autre.
Leur attribution reste explicite, auditée et bornée à la préproduction. La
réactivation possède son propre amorçage et son propre verrou d’activation ;
relancer l’amorçage historique de la suspension ne peut donc pas élargir
silencieusement les pouvoirs d’une personne.

## Invariants de sécurité

Après contrôle de la permission exacte, de l’état attendu `suspended`, de la
cible scellée, du jeton CSRF et d’une justification de 20 à 500 caractères, le
service :

1. verrouille l’identité cible ;
2. vérifie qu’elle est toujours suspendue ;
3. verrouille et contrôle l’absence de toute session encore active ;
4. passe l’identité à `active` ;
5. inscrit l’événement `identity.reactivated` dans la chaîne d’audit ;
6. valide l’ensemble dans une transaction unique.

Si une session active subsiste ou apparaît concurremment, toute l’opération est
annulée. Les sessions révoquées restent révoquées. Les sessions expirées ne sont
ni modifiées ni prolongées. L’événement d’audit inscrit explicitement
`restored_sessions: 0`.

## Interface et minimisation

La console présente l’action seulement pour une identité suspendue et seulement
à une personne disposant du pouvoir de réactivation. Elle n’expose aucun cookie,
secret, identifiant technique de session ou empreinte. La cible réelle voyage
dans un jeton chiffré, authentifié, lié à l’opérateur et de courte durée.

## Validation locale

La validation complète réussit :

- **242 tests Node.js** ;
- **63 tests Python** ;
- séparation stricte des pouvoirs de suspension et de réactivation ;
- transition MariaDB et audit dans une transaction unique ;
- rollback complet lorsqu’une session active subsiste ;
- conservation inchangée des sessions révoquées et expirées ;
- refus des cibles ou états périmés, des jetons altérés et des demandes sans
  permission exacte ;
- chaîne d’audit valide et absence de restauration de session.

## Activation prévue en préproduction

La mise en service devra suivre les mêmes garde-fous que le lot 54 : sauvegarde
vérifiée, release immuable, publication du catalogue version 6, attribution
auditée du rôle par son amorçage séparé, redémarrage contrôlé, recette avec l’identité de recette
actuellement suspendue, puis contrôle direct de la base et de la chaîne d’audit.

La recette devra prouver que l’identité redevient active avec **zéro session
active restaurée**, puis qu’une nouvelle authentification est nécessaire. La
production et N09 – Énergie restent hors périmètre tant que cette recette n’est
pas formellement terminée.
