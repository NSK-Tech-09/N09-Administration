# Lot 57 — contrat scellé de promotion en production

Statut : **implémenté localement, aucune mutation de production**

Date : **14 août 2026**

## Objet

Transformer le passage en production d’Administration et de N09 – Suivi des
tâches en une décision reproductible, vérifiable et interruptible. Le lot ajoute
un validateur sans effet de bord : il lit un manifeste, refuse tout dossier
incomplet et produit une empreinte SHA-256 seulement si tous les prérequis sont
réunis.

Le validateur ne se connecte ni à MariaDB, ni à Infomaniak, ni à GitHub. Il ne
déploie rien, ne modifie aucune configuration et ne connaît aucun secret.

## Périmètre obligatoire

Le manifeste contient exactement deux composants :

- `n09-administration`, issu de `NSK-Tech-09/N09-Administration`, destiné à
  `https://admin.nsktech.fr` avec le contrôle `/health` ;
- `n09-suivi-taches`, issu de `NSK-Tech-09/N09-Suivi-des-taches`, destiné à
  `https://taches.nsktech.fr` avec le contrôle `/api/health`.

Chaque composant désigne un commit complet, l’empreinte de l’artefact immuable,
la release identique à celle testée, une base suffixée `_prod`, les résultats de
tests, une sauvegarde de production restaurée lors d’un exercice et une release
antérieure accompagnée de la preuve de sa procédure de repli.

## Refus par défaut

Le Go est refusé si :

- un secret, mot de passe, jeton, clé privée ou valeur factice apparaît dans le
  manifeste ;
- un commit, une empreinte, une origine, une base ou un chemin de santé n’est pas
  strictement conforme ;
- les tests sont inférieurs aux suites déjà validées en préproduction : 250
  tests Node.js et 63 Python pour Administration, 213 tests Node.js pour Tâches ;
- la sauvegarde n’a pas de preuve de restauration antérieure à la décision ;
- la release de repli est absente ou identique à la release promue ;
- la décision humaine n’est pas reliée à une identité NSK et à une fenêtre de
  changement future de quatre heures au maximum ;
- les artefacts diffèrent de la préproduction, les bases ne sont pas isolées,
  DNS/TLS ne sont pas prêts ou l’invalidation des anciennes sessions n’est pas
  planifiée ;
- un canal externe de notification est ouvert ;
- N09 – Énergie n’est pas explicitement déclaré inchangé.

## Preuve produite

`npm run verify:production-promotion -- <manifeste.json>` renvoie uniquement :

- l’identifiant de changement ;
- les deux applications, leurs commits et empreintes d’artefact ;
- l’empreinte canonique SHA-256 du manifeste ;
- le verdict `ready: true`.

Le moindre échec renvoie seulement `production_promotion_refused` et un code de
sortie non nul. Aucun contenu potentiellement sensible n’est recopié dans les
journaux.

## Validation locale

- **11 scénarios dédiés** couvrent le Go nominal, l’empreinte canonique et les
  refus de secret, champ ambigu, cible de préproduction, artefact mutable,
  preuve de tests insuffisante, sauvegarde non restaurée ou ancienne, repli
  invalide, composant dupliqué, fenêtre incohérente, canal externe et mutation
  de N09 – Énergie ;
- la suite complète atteint **261 tests Node.js** réussis ;
- les **63 tests Python** de conformité restent réussis ;
- `git diff --check` ne relève aucune anomalie.

## Séquence après fusion

1. préparer les deux cibles de production isolées sans changer les DNS publics ;
2. promouvoir les artefacts exacts déjà recettés, sans reconstruction ;
3. créer puis restaurer les sauvegardes de production et sceller leurs preuves ;
4. compléter le manifeste hors dépôt, sans secret ;
5. obtenir un verdict Go et conserver son empreinte avec la décision humaine ;
6. exécuter la fenêtre par paliers : Administration, contrôle, Tâches, contrôle,
   puis seulement le basculement public ;
7. interrompre et revenir aux releases précédentes au premier contrôle rouge ;
8. invalider les sessions historiques et vérifier l’audit après le basculement.

Cette séquence applique `REL-001`, `REL-002`, `ARC-010`, `ARC-012`, `ARC-013`,
`ARC-016` et `TST-001`. La production actuelle, ses DNS, ses bases et N09 –
Énergie restent inchangés par le lot 57.
