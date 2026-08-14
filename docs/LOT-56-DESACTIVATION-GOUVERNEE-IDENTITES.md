# Lot 56 — désactivation gouvernée des identités

Statut : **publié, déployé et validé en préproduction**

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

## Déploiement et recette en préproduction

Le **14 août 2026**, le commit canonique
`c0c260155a359993b2cea9e23e2ae30dabab1aac` a été activé dans la release
immuable `releases/c0c2601`. L’archive complète porte l’empreinte SHA-256
`d139ea4a897b3a77a458dae6c85449733ff47acee765e83e3ef5c8b2396b987d` ;
**194 fichiers source**, **250 tests Node.js** et **63 tests Python** ont été
validés sur Infomaniak avant l’activation.

La sauvegarde MariaDB préalable
`/srv/customer/backups/preprod-admin/lot56-pre-identity-disablement-20260814T051834Z.sql.gz`
pèse **34 168 octets**, est valide au format gzip, protégée en mode `600` et
porte l’empreinte
`2ea373936bfd21acd1c38a78451c939dd9505b0f74c910d1b3936c388c982974`.
Les déclencheurs, non exportables par le compte d’exécution sans privilège
`TRIGGER`, restent versionnés dans le schéma de la release et n’ont pas changé.

Le catalogue Administration v7 est publié avec l’empreinte
`b06c3253693cf3e72013dff121f458846dc3a32e059d5c36b2da490a0af2ed13`.
Sa seconde publication n’a créé aucun doublon. L’amorçage séparé du rôle
`identity-disablement-administrator` a créé une seule affectation pour
l’identité principale ; son second passage est également idempotent. Les deux
opérations ont laissé la chaîne d’audit valide.

L’enregistrement de la nouvelle commande Node Builder n’a pas remplacé le
processus déjà en mémoire. Le contrôle fonctionnel a détecté que le lot 55
restait servi malgré un premier redémarrage. Un arrêt puis un démarrage
explicites ont chargé `releases/c0c2601`. La sonde `/health` répond alors
`{"status":"ok"}` et la console expose effectivement la permission
`administration:identities:disable` ainsi que l’interdiction de
l’auto-désactivation.

La recette irréversible a utilisé une identité explicitement jetable :

- identité `70b77ba9-4dbb-49e3-b8ee-e677df2a89ed` ;
- adresse dédiée `travers.fred.09+lot56-desactivation@gmail.com` ;
- aucune session active avant la décision ;
- une affectation temporaire `tasks-reader` sur le périmètre
  `site_lot56_disablement_recipe` ;
- état final `disabled` ;
- **0 session active**, **0 affectation active** et **1 affectation révoquée** ;
- chaîne d’audit valide après la transaction.

Les identités **Fred TRAVERS** et **Fred TRAVERS — Recette** restent actives et
inchangées. La preuve de recette
`/srv/customer/backups/preprod-admin/lot56-disablement-recipe-proof-20260814T055123Z.txt`
est protégée en mode `600` et porte l’empreinte
`234139ceeda169ab0dcf4d914ceb7d02f8031c1c0648048bca88f1c3b5a2bfea`.

`releases/5d64bc1` et la sauvegarde préalable restent disponibles pour retour
arrière. La production et N09 – Énergie n’ont pas été modifiées.
