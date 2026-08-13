# Lot 52 — Seconde identité humaine de recette

Statut : **déployé et validé en préproduction**

Date : **13 août 2026**

## Objet

Ce lot introduit une seconde identité humaine distincte afin de vérifier
l'isolation entre personnes dans N09 – Administration et N09 – Suivi des
tâches. Cette identité reste pilotée par Fred TRAVERS pendant la recette, mais
possède son propre compte Infomaniak et son propre identifiant NSK immuable.

Le second compte Infomaniak utilise `travers.fred.09@gmail.com`. L'adresse
`fred.recette@nsktech.fr`, alias de `f.travers@nsktech.fr`, reste disponible
comme adresse fonctionnelle de recette sans consommer une nouvelle boîte mail.
Aucune adresse ni aucun nom n'est utilisé pour rattacher automatiquement les
identités : seul le couple OIDC exact `issuer + subject` fait foi.

## Identité NSK créée

La commande contrôlée `human-identity-preprod-cli.mjs` a créé l'identité :

- nom : **Fred TRAVERS — Recette** ;
- courriel : `travers.fred.09@gmail.com` ;
- identifiant NSK : `ac31d4fa-ca3f-4d34-87b3-3d8e436b30de` ;
- état : `active` ;
- affectations actives après création : **0** ;
- chaîne d'audit : **valide**.

L'opérateur était l'identité principale
`60a40cd7-f2a4-4393-8021-9f806b42b41a`. La création a été réalisée par
l'outil applicatif prévu, sans insertion SQL manuelle et sans exposer de secret.

## Rattachement OIDC réel

Le parcours a été exécuté dans une session Chrome isolée avec le second compte
Infomaniak :

1. la première connexion a présenté une preuve OIDC valide ;
2. l'identité externe inconnue est restée en état `link_required` ;
3. aucune identité, aucun rôle et aucun droit n'ont été créés automatiquement ;
4. une demande temporaire de rattachement a été enregistrée ;
5. l'identité administratrice principale a approuvé nominativement la demande
   vers **Fred TRAVERS — Recette**, avec une justification explicite ;
6. le registre a confirmé deux identités actives et six affectations actives,
   toutes conservées sur l'identité principale ;
7. après renouvellement de la session, le second compte a été reconnu comme
   **rattaché** à son identité NSK distincte.

## Défaut découvert et corrigé

La première recette a révélé qu'une session encore `link_required` ne pouvait
pas être fermée lorsque le registre des sessions Administration était en mode
`enforce`. Cette session locale ne possède pourtant aucune session centrale :
le service tentait de révoquer une preuve inexistante et répondait `503`, ce qui
empêchait le renouvellement après approbation.

La PR **#59** a corrigé cette contradiction sans affaiblir la sécurité :

- une session `link_required` est désormais fermée localement ;
- une session `authenticated` exige toujours la révocation centrale confirmée ;
- tout autre état inattendu reste refusé ;
- un test de non-régression dédié protège le comportement.

La PR a été fusionnée dans `main` avec le commit canonique
`16399df2b53a009d2592c3511be7fa7055d43d0a`. La release immuable
`releases/16399df` a réussi **211 tests Node.js** et **63 tests Python** sur
Infomaniak avant la bascule. Les contrôles public et local de `/health` ont
répondu `{"status":"ok"}` après le redémarrage explicite du processus.

La release précédente `releases/dbf951a` et la sauvegarde de données préalable
restent disponibles pour un retour arrière conservateur.

## Recette d'isolation finale

La recette Chrome effectuée après redémarrage confirme :

- la fermeture de l'ancienne session `link_required` fonctionne ;
- la reconnexion Infomaniak reconnaît **Fred TRAVERS — Recette** comme identité
  NSK rattachée ;
- aucun lien d'administration n'est proposé à cette identité ;
- l'accès direct à `/admin/access` est refusé faute de permission dédiée ;
- la connexion à N09 – Suivi des tâches est refusée faute d'autorisation
  centrale et aucun accès applicatif n'est ouvert ;
- l'écran personnel ne présente que la session Administration courante de
  l'identité de recette et aucune session de l'identité principale ;
- aucun avertissement applicatif significatif n'est apparu dans le navigateur.

Le lot démontre donc de bout en bout que rattacher une personne ne lui accorde
aucun privilège, que deux identités restent étanches et que chaque accès exige
une affectation explicite séparée.

## Invariants préservés

- aucun mot de passe ou code Infomaniak dans Git, la base ou les journaux ;
- aucun rapprochement par courriel ou nom ;
- aucun rôle, site ou droit accordé pour faciliter la recette ;
- aucune donnée de production ni modification de N09 – Énergie ;
- aucune insertion SQL manuelle contournant l'audit ;
- aucune promotion en production incluse dans ce lot.

## Références

- `ADR-003-IDENTITES-FEDEREES.md`
- `ADR-007-DEMANDES-RATTACHEMENT-NODE.md`
- `ADR-008-ADMINISTRATION-RATTACHEMENTS.md`
- `ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`
- `CONTRAT-IDENTITE-ACCES.md`
- PR GitHub **#57** : préparation de l'identité humaine contrôlée
- PR GitHub **#58** : indépendance du test MariaDB vis-à-vis du fuseau
- PR GitHub **#59** : renouvellement après rattachement
