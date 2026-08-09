# ADR-003 — Identité NSK stable et fournisseurs de connexion multiples

## Décision

N09 – Administration attribue à chaque personne un identifiant NSK immuable.
Les moyens de connexion externes sont des preuves d'identité rattachées à ce
compte, jamais le compte lui-même.

Un rattachement est identifié par le couple OIDC exact `issuer + subject`.
L'adresse électronique, le nom affiché et les autres attributs déclaratifs ne
sont jamais utilisés pour rattacher automatiquement deux comptes.

## Expérience visée

Une même personne peut utiliser, selon les options activées :

- son compte Infomaniak ;
- un lien de connexion reçu par courrier électronique ;
- une passkey ;
- un autre fournisseur compatible OIDC.

Après authentification, toutes ces méthodes aboutissent au même compte NSK et
aux mêmes droits. La suspension du compte NSK bloque immédiatement tous les
moyens de connexion associés.

## Premier fournisseur

Infomaniak Auth sera le premier adaptateur évalué car il est déjà disponible
dans l'organisation, repose sur OAuth2/OpenID Connect et n'ajoute pas
d'infrastructure. Il reste facultatif : aucune règle métier ni identité NSK ne
dépend de son adresse électronique ou d'un identifiant propre au fournisseur.

## Rattachement sûr

Un premier accès inconnu ne crée aucun droit et ne fusionne aucun compte. Il
aboutit à `link_required`. Le rattachement nécessite ensuite une invitation,
une approbation administrative ou la preuve d'une session NSK existante.

Cette étape sera conçue avec une protection contre la substitution de compte,
une durée courte et un événement d'audit obligatoire.

## Conséquences

- un utilisateur peut changer de fournisseur sans perdre ses droits ;
- plusieurs fournisseurs peuvent coexister ;
- le départ d'un fournisseur n'impose pas de migration des données métier ;
- N09 – Administration ne stocke aucun mot de passe externe ;
- l'exploitation doit permettre la révocation séparée de chaque rattachement.
