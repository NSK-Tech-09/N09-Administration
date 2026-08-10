# ADR-008 – Administration authentifiée des rattachements

Statut : **Acceptée pour la préproduction**
Date : **10 août 2026**

## Contexte

Les demandes de rattachement sont persistées et auditées, mais leur traitement
ne doit être ni anonyme, ni confondu avec le simple fait de posséder une identité
NSK rattachée à Infomaniak.

## Décision

La consultation, l'approbation et le refus sont exposés dans une interface du
service Node. L'accès exige simultanément :

- une session OIDC NSK valide et rattachée ;
- une identité NSK active ;
- l'application centrale `n09-administration` active ;
- une affectation active portant exactement la permission
  `administration:identity-links:decide` ;
- une preuve CSRF propre à la session pour toute décision.

L'interface ne montre jamais le sujet technique fourni par l'émetteur OIDC.
Elle présente seulement les indices nécessaires au contrôle humain, les dates
et la référence de la demande. L'approbation cible exclusivement une identité
NSK active. Toute décision exige une justification, s'exécute dans la même
transaction que son événement d'audit et ne crée aucune affectation métier.

## Premier administrateur

Le premier pouvoir administratif est amorcé par une commande opérateur séparée,
idempotente et réservée à une base `_preprod`. Elle exige un indicateur
d'activation, l'UUID exact de l'identité et une justification explicite. Cette
commande crée au besoin l'application centrale et l'unique affectation dédiée,
puis vérifie la chaîne d'audit. Elle n'est jamais lancée au démarrage du service.

## Conséquences

- être connecté ou rattaché ne suffit jamais à administrer ;
- un privilège générique ou technique ne remplace pas la permission exacte ;
- les anciennes sessions doivent être renouvelées pour recevoir leur preuve
  CSRF ;
- attribution du premier pouvoir, publication du code et déploiement restent
  trois décisions distinctes et réversibles.
