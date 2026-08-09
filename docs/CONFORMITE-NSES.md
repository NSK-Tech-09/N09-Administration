# Conformité au référentiel NSES

Référentiel observé : `N09-Referentiel-ingenierie-logicielle`, version **0.70**.
Ce document trace l’application des règles sans les recopier ni les remplacer.

## Paquet applicable

Le paquet normatif `IDENTITE-ACCES` chargé pour le noyau actuel contient
`GEN-001`, `ARC-001` à `ARC-016`, `ERG-001`, `ERG-002` et `TST-001`.

## Décisions déjà matérialisées

- identité centrale et cycle de vie explicite (`ARC-001`, `ARC-004`) ;
- décision `Sujet + Application + Rôle + Périmètre + Conditions`, refus par
  défaut et contrôle serveur (`ARC-002`, `ARC-012`) ;
- aucun passe-droit métier pour le super-administrateur (`ARC-003`) ;
- affectations directes ou héritées d’un groupe (`ARC-005`) ;
- groupes nommés, délégations bornées et décisions applicatives indépendantes
  (`ARC-005`, `ARC-007`, `ERG-002`) ;
- séparation du service d’identité, de la console et des applications métier
  (`ARC-006`) ;
- politiques fermée, sur invitation ou soumise à validation (`ARC-007`) ;
- catalogue applicatif versionné (`ARC-011`) ;
- périodes, suspension et révocation testables (`ARC-010`, `TST-001`).
- rattachements externes séparés de l'identité NSK, temporaires, refusés par
  défaut et sans affectation implicite (`ARC-001`, `ARC-002`, `ARC-010`) ;
- journal append-only, données minimisées et écritures atomiques (`ARC-013`,
  `ARC-014`, `TST-003`) ;
- structure, configuration factice et absence de dépendance superflue
  (`DEV-001` à `DEV-003`).

## Obligations des incréments suivants

- authentification standard, MFA privilégiée, récupération forte et sessions
  révocables (`ARC-008` à `ARC-010`) ;
- groupes, délégations et demandes conservés avec leur audit dans une transaction
  centrale indivisible (`ARC-005`, `ARC-007`, `ARC-013`) ;
- archivage externe du journal, notifications centrales et restauration
  éprouvée (`ARC-013`, `ARC-015`, `ARC-016`) ;
- interface expliquant droits directs, hérités et effectifs (`ERG-001`).

Les paquets d’interface et de profil Web seront chargés au début de l’incrément
concerné, conformément au principe de contexte minimal du référentiel.
