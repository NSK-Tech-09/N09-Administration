# Lot 43 — Socle du registre de sessions révocables

Statut : **implémenté et validé localement, non publié et non déployé**

Date : **13 août 2026**

## Objet

Ce lot matérialise le premier incrément strictement additif de
`ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`. Il ne modifie aucun parcours de
connexion actif et n’inscrit aucune session réelle.

## Réalisé

- création d’un identifiant opaque et d’un secret aléatoire de 256 bits ;
- conservation exclusive de l’empreinte SHA-256 du secret dans le registre ;
- liaison stricte à une identité et une application ;
- échéances distinctes après inactivité et absolue ;
- prolongation bornée par l’échéance absolue ;
- révocation versionnée avec auteur facultatif et cause obligatoire ;
- comparaison de l’empreinte en temps constant ;
- codes de refus distincts pour session inconnue, contexte incohérent, secret
  invalide, révocation, inactivité et échéance absolue ;
- table MariaDB additive `application_sessions`, avec clés étrangères,
  contraintes de cohérence et index d’exploitation.

La charge persistée ne contient ni secret brut, ni cookie, ni jeton du
fournisseur d’identité. La description de contexte est bornée à 255 caractères
et ne constitue pas une empreinte d’appareil.

## Validation locale

La suite complète de N09 – Administration réussit le 13 août 2026 :

- **162 tests réussis** ;
- **0 échec** ;
- génération sans secret brut dans le registre ;
- refus des durées incohérentes ou supérieures au plafond ;
- isolation identité/application ;
- refus après inactivité, échéance absolue ou révocation ;
- refus fermé d’un enregistrement dont les échéances sont invalides ;
- prolongation sans dépassement de la durée absolue ;
- contrôle structurel du schéma MariaDB.

## Frontière volontaire

Le lot ne branche pas encore le registre sur le retour OIDC, le courtage de
connexion applicative, les décisions d’accès ou la déconnexion. Il ne fournit
pas non plus l’interface personnelle de consultation.

Cette séparation est intentionnelle : le schéma et les invariants sont d’abord
vérifiés sans modifier les sessions existantes. Le prochain incrément devra
ajouter la persistance transactionnelle et l’audit, puis fonctionner en mode
d’observation avant toute décision opposable.

## Absence d’impact externe

- aucune migration n’a été appliquée à la base de préproduction ;
- aucune release n’a été créée ni redémarrée ;
- aucun cookie actif n’a été invalidé ;
- aucune identité, affectation ou session utilisateur n’a été modifiée ;
- aucune publication GitHub n’a été effectuée.

## Prochain contrôle

Avant publication ou déploiement, une revue doit confirmer ensemble :

1. le schéma additif et sa procédure de retour arrière ;
2. les écritures transactionnelles avec le journal d’audit central ;
3. le mode d’observation sans effet sur les sessions actuelles ;
4. le contrat serveur à serveur avec N09 – Suivi des tâches ;
5. la fenêtre bornée de sortie des anciens cookies autonomes.

## Références

- `ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`
- `ARC-010`
- `ARC-013`
- `ERG-016`
- `ERG-032`
- `TST-001`
