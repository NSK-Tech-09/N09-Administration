# ADR-024 — Un périmètre global couvre les sous-périmètres de l’application

Statut : **Acceptée**

Date : **17 août 2026**

## Contexte

Le registre sait conserver des affectations par site et des affectations
globales. La décision centrale exigeait pourtant jusqu’ici une égalité stricte
entre le périmètre demandé et celui de l’affectation. Un rôle global ne pouvait
donc pas autoriser une opération portant sur un site précis.

Cette égalité obligeait à dupliquer un octroi administrateur pour chaque site et
à recommencer à chaque création de site. Elle contredisait la définition publiée
du périmètre `global` : ensemble de l’application.

## Décision

Une affectation globale active peut satisfaire une demande portant sur un
sous-périmètre de la même application lorsque toutes les autres frontières sont
respectées :

- même identité ;
- même application ;
- permission exacte présente ;
- période de validité respectée ;
- toutes les conditions applicatives confirmées.

Une affectation contextualisée continue de ne couvrir que son périmètre exact.
Le changement ne crée aucun héritage entre applications et ne transforme jamais
une permission d’administration technique en permission métier.

## Conséquences

- un rôle applicatif explicitement publié avec une portée globale peut gouverner
  les opérations contextualisées de cette application ;
- les profils ordinaires restent soumis aux affectations de site ;
- l’application métier reste responsable de confirmer ses rôles locaux et ses
  périmètres avant chaque décision ;
- l’octroi global reste une mutation humaine auditée, justifiée et révocable.

## Validation

Les vecteurs de décision couvrent désormais l’écriture demandée sur un site à
partir d’une affectation globale portant `tasks:write`. Les refus existants
restent couverts : identité inactive, application inactive, permission absente,
condition manquante et autre application.
