# Lot 52 — Seconde identité humaine de recette

Statut : **préparé, non déployé**

Date : **13 août 2026**

## Objet

Ce lot prépare une seconde identité humaine distincte afin de vérifier
l'isolation entre personnes dans N09 – Administration et N09 – Suivi des
tâches. Cette identité reste pilotée par Fred TRAVERS pendant la recette, mais
possède son propre compte Infomaniak et son propre identifiant NSK immuable.

Le second compte Infomaniak a été créé avec `travers.fred.09@gmail.com`.
L'adresse `fred.recette@nsktech.fr`, alias de `f.travers@nsktech.fr`, reste
disponible comme adresse fonctionnelle de recette sans consommer une nouvelle
boîte mail. Aucune de ces adresses n'est utilisée pour rattacher
automatiquement les identités : seul le couple OIDC `issuer + subject` fait
foi.

## Création contrôlée

La commande `human-identity-preprod-cli.mjs` :

- exige une activation explicite et refuse toute base autre que `_preprod` ;
- exige l'identité exacte d'un opérateur NSK actif et une justification ;
- normalise et vérifie le courriel et le nom d'affichage ;
- crée une identité active sans affectation ni permission ;
- inscrit la création et son auteur dans la chaîne d'audit atomique ;
- reste idempotente pour une définition strictement identique ;
- refuse les collisions d'identifiant ou de courriel ;
- vérifie enfin la chaîne d'audit et l'absence de droit actif.

Le nom prévu est **Fred TRAVERS — Recette**. La création effective ne sera
réalisée qu'après publication de l'outil et création du second compte
Infomaniak.

## Parcours de rattachement

1. utiliser le second compte Infomaniak créé avec
   `travers.fred.09@gmail.com` ;
2. ouvrir N09 – Administration dans un navigateur isolé et lancer la connexion ;
3. constater une demande temporaire `link_required`, sans compte ni droit créé
   automatiquement ;
4. depuis l'identité administratrice actuelle, approuver la demande vers
   **Fred TRAVERS — Recette** avec une justification explicite ;
5. renouveler la connexion de recette et constater l'identité distincte ;
6. vérifier qu'elle ne voit aucune session de l'identité principale, ne peut en
   fermer aucune et n'accède à aucune application sans affectation ;
7. vérifier la chaîne d'audit, puis conserver l'identité comme moyen permanent
   de recette de non-régression.

## Interdictions

- aucun mot de passe Infomaniak dans Git, la base ou les journaux ;
- aucun rapprochement par courriel ou nom ;
- aucun rôle, site ou droit accordé pour faciliter la recette ;
- aucune donnée de production ni modification de N09 – Énergie ;
- aucune insertion SQL manuelle contournant l'audit.

## Références

- `ADR-003-IDENTITES-FEDEREES.md`
- `ADR-007-DEMANDES-RATTACHEMENT-NODE.md`
- `ADR-008-ADMINISTRATION-RATTACHEMENTS.md`
- `ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`
- `CONTRAT-IDENTITE-ACCES.md`
