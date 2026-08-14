# Lot 56 — désactivation gouvernée des identités

Statut : **implémenté et validé localement, non publié et non déployé**

Date : **14 août 2026**

## Objet

Fermer proprement le cycle de vie d’une identité qui ne doit plus pouvoir
accéder à l’écosystème NSK Tech 09. La désactivation est plus forte qu’une
suspension temporaire : elle coupe l’accès existant et futur sans supprimer
l’identité, son historique ni ses preuves d’audit.

Une identité `active` ou `suspended` peut passer à `disabled`. Une identité
désactivée n’est pas réactivable depuis la console de cycle de vie. Toute
éventuelle procédure de retour devra faire l’objet d’une décision et d’un lot
distincts, afin qu’une sortie définitive ne puisse pas être annulée par erreur.

## Séparation des responsabilités

Le catalogue Administration passe en version 7 et ajoute exactement :

- la permission `administration:identities:disable` ;
- le rôle global `identity-disablement-administrator` ;
- l’action de désactivation dans la console `/admin/identities`.

Ce pouvoir est distinct des permissions de suspension et de réactivation. Son
attribution possède un amorçage dédié, protégé par la variable
`N09_ALLOW_IDENTITY_DISABLEMENT_BOOTSTRAP`. Une personne qui détient elle-même
ce pouvoir ne peut pas être désactivée par ce parcours : le retrait d’une
autorité de désactivation exige une gouvernance séparée et explicite.

## Transaction atomique

Après contrôle de la permission exacte, de la cible scellée, du jeton CSRF, de
l’état attendu et d’une justification de 20 à 500 caractères, le service :

1. verrouille l’identité cible ;
2. verrouille toutes ses sessions applicatives encore actives ;
3. verrouille toutes ses affectations d’accès encore actives ;
4. passe l’identité à `disabled` ;
5. révoque les sessions actives ;
6. révoque les affectations actives ;
7. inscrit chaque transition dans la chaîne d’audit avec une corrélation
   commune ;
8. valide l’ensemble dans une transaction unique.

Si l’identité, une session ou une affectation change concurremment, toute
l’opération est annulée. Il n’existe donc aucun intervalle où l’identité serait
désactivée tout en conservant une session ou une affectation active.

## Conservation et minimisation

La désactivation ne supprime ni :

- l’identité et son identifiant immuable ;
- les liens avec les fournisseurs d’identité externes ;
- les sessions et affectations historiques ;
- les décisions et événements d’audit.

Ces données restent nécessaires à l’intégrité du référentiel et à la preuve des
décisions antérieures. Elles deviennent inopposables : le moteur d’accès refuse
toute identité dont l’état n’est pas `active`, même en présence d’une ancienne
affectation.

La console n’expose aucun cookie, secret ou identifiant technique de session.
Elle interdit l’auto-désactivation et n’affiche l’action qu’aux opérateurs
autorisés, pour une autre identité `active` ou `suspended`.

## Validation locale

La validation complète du périmètre réussit :

- **250 tests du service Node.js** ;
- reconstruction réussie du démonstrateur et test de rendu réussi, soit **251
  tests Node.js** sur l’ensemble du dépôt ;
- **63 tests Python** ;
- séparation stricte des trois pouvoirs de cycle de vie ;
- transaction atomique en mémoire et MariaDB ;
- révocation simultanée des sessions et affectations actives ;
- rollback complet en cas de concurrence ;
- refus de l’auto-désactivation et du retrait direct d’une autre autorité de
  désactivation ;
- refus d’accès explicite pour une identité `disabled` ;
- absence de restauration ou de suppression de données historiques.

Le démonstrateur visuel n’est pas modifié par ce lot. Ses dépendances verrouillées
ont été restaurées localement, sa construction Vinext réussit et son test de
rendu est vert.

## Déploiement futur en préproduction

Le déploiement devra rester une opération distincte et autorisée. Il comprendra
au minimum :

1. une sauvegarde MariaDB vérifiée et empreintée ;
2. la construction d’une release immuable depuis le commit canonique ;
3. l’exécution des suites Node.js et Python sur Infomaniak ;
4. la publication idempotente du catalogue Administration v7 ;
5. l’amorçage séparé du rôle de désactivation ;
6. le redémarrage contrôlé du service ;
7. une recette sur une identité de test non privilégiée ;
8. la vérification directe de l’état, des sessions, des affectations et de la
   chaîne d’audit ;
9. la conservation de la release précédente et de la sauvegarde pour retour
   arrière.

La production et N09 – Énergie ne sont pas concernées par la préparation locale
de ce lot.
