# ADR-015 – Octrois applicatifs gouvernés et confirmation locale continue

Statut : **acceptée, validation en préproduction à réaliser**

## Contexte

Administration sait publier les catalogues applicatifs et révoquer une
affectation centrale. Créer un octroi à partir de champs libres réintroduirait
toutefois une seconde définition des rôles et pourrait autoriser un accès sans
profil métier exploitable dans l'application cible.

N09 – Suivi des tâches conserve notamment son profil `application_users`, son
rôle métier et ses appartenances de sites. Administration ne doit ni les
copier, ni les déduire d'une adresse électronique, ni considérer leur existence
comme acquise sur la seule déclaration d'un opérateur humain.

## Décision

Un responsable possédant `administration:access:decide` peut accorder un accès
uniquement à partir du dernier catalogue publié par l'application :

- l'identité et l'application doivent être actives ;
- le rôle, ses permissions et le type de périmètre doivent être `active` ;
- la version du catalogue affichée doit toujours être la dernière ;
- un périmètre non global exige son identifiant exact ;
- la justification comporte de 20 à 500 caractères ;
- l'application N09 – Administration et ses pouvoirs protégés sont exclus de ce
  parcours général.

Lorsque le catalogue déclare
`readiness: application_confirmation_required`, chaque prérequis publié devient
une condition de l'affectation centrale. L'application doit présenter ces
conditions comme satisfaites à chaque décision d'accès, après ses propres
contrôles serveur. Un octroi central ne suffit donc jamais à contourner un
profil absent, un rôle local insuffisant ou un site non attribué.

L'identifiant d'une affectation est stable pour le quintuplet personne,
application, rôle, type de périmètre et périmètre. Une répétition identique est
idempotente. Après révocation, un nouvel octroi réactive la même affectation en
incrémentant sa version. Deux décisions concurrentes ne peuvent ainsi créer
deux droits équivalents.

La mutation et l'événement `assignment.granted` sont écrits dans la même
transaction. L'audit conserve le décideur, la justification, le catalogue, les
permissions, les conditions, le périmètre et la version.

## Conséquences

- aucun rôle ni périmètre libre ne peut être inventé depuis l'interface ;
- un élément `planned` ou `deprecated` ne peut pas être accordé ;
- publier un catalogue n'accorde toujours aucun droit ;
- l'application reste l'autorité de ses données métier ;
- retirer un rôle encore utilisé reste bloqué par la compatibilité des
  catalogues ;
- les octrois de gouvernance centrale exigent toujours une procédure dédiée ;
- le premier octroi réel de Suivi des tâches restera impossible tant que son
  catalogue ne publiera pas un rôle d'écriture actif et que l'application ne
  confirmera pas les prérequis à chaque requête.

## Retour arrière

Le service précédent peut être réactivé sans migration de schéma. Les
affectations créées restent lisibles et révocables ; aucune donnée métier n'est
copiée. Avant tout retour arrière, tout octroi réalisé par cette version doit
être inventorié afin d'éviter qu'un droit actif devienne invisible dans
l'ancienne interface.

## Validation attendue

- suite Node complète réussie localement et sur la release immuable ;
- publication idempotente du catalogue Administration version 2 ;
- refus d'un rôle planifié, d'un catalogue périmé et d'un périmètre invalide ;
- refus CSRF sans mutation ;
- octroi conditionnel, répétition idempotente, révocation puis réactivation
  versionnée sur un jeu de validation sans donnée métier réelle ;
- chaîne d'audit valide et retour arrière conservé.
