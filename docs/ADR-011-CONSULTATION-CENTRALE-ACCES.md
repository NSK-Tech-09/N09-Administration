# ADR-011 – Consultation centrale des utilisateurs et des accès

Statut : **Acceptée pour la préproduction**
Date : **10 août 2026**

## Contexte

N09 – Administration doit devenir le point de contrôle compréhensible de
l'écosystème sans transformer la simple consultation du registre en pouvoir de
modifier les droits. La permission existante de décision sur les rattachements
ne couvre pas cette responsabilité.

## Décision

Une première interface authentifiée expose en lecture seule :

- les identités NSK et leur état ;
- les applications enregistrées, leur état et leur politique d'inscription ;
- les affectations, rôles, permissions, périmètres, états, motifs et versions.

L'accès exige une session OIDC NSK rattachée, une identité active,
l'application centrale active et la permission exacte
`administration:access:read`. Cette permission est amorcée séparément par une
commande opérateur idempotente, limitée à une base `_preprod`, justifiée et
auditée.

La permission `administration:identity-links:decide` ne donne aucun accès à ce
registre. Réciproquement, `administration:access:read` ne permet ni de traiter
un rattachement, ni de créer, modifier, suspendre ou révoquer une affectation.

L'interface n'expose aucune preuve OIDC, aucun sujet fournisseur, aucun secret
et aucun formulaire de mutation. Toute méthode autre que `GET` est refusée.

## Conséquences

- la lecture et la décision restent deux responsabilités distinctes ;
- le premier écran opérationnel peut être déployé sans ouvrir de capacité
  d'écriture ;
- les futurs actes de création, suspension, révocation ou délégation devront
  chacun disposer d'une permission dédiée, d'une justification, d'une preuve
  CSRF et d'un événement d'audit transactionnel ;
- une indisponibilité du registre ferme l'écran sans modifier les accès.

## Retour arrière

La release précédente peut être réactivée sans migration de schéma. Révoquer
l'affectation `access-directory-reader` retire immédiatement l'accès à l'écran.
Les objets déjà présents dans le registre ne sont ni transformés ni dupliqués.
