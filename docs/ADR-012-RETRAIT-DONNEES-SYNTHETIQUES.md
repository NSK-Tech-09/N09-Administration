# ADR-012 – Retrait audité des données synthétiques de préproduction

Statut : **Acceptée pour la préproduction**

## Contexte

Le jeu synthétique initial a permis de valider le stockage, la décision d'accès
et la chaîne d'audit avant l'introduction de toute identité réelle. Le registre
opérationnel rend désormais ces objets visibles ; ils ne doivent plus compter
parmi les accès actifs.

Une suppression physique ferait disparaître le contexte historique et serait
incompatible avec le principe de preuve durable des décisions.

## Décision

Le retrait s'effectue dans l'ordre suivant :

1. révocation de l'affectation synthétique, avec passage en version 2 ;
2. archivage de l'identité synthétique ;
3. passage de l'application synthétique à l'état `retired`.

Chaque mutation conserve l'identifiant immuable, exige l'identité NSK active de
l'opérateur et une justification explicite, puis écrit son événement d'audit
dans la même transaction que la donnée concernée. La révocation intervient en
premier afin qu'une interruption éventuelle laisse toujours le système dans un
état plus restrictif. La commande est idempotente et limitée à une base dont le
nom se termine par `_preprod`.

Avant toute mutation, les trois objets sont comparés à leur définition
synthétique contrôlée. Une absence partielle, une collision ou une altération
inattendue bloque l'opération.

## Conséquences

- aucun objet n'est supprimé physiquement ;
- le tableau de bord conserve l'histoire avec les états `archived`, `retired`
  et `revoked` ;
- les compteurs ne dénombrent plus que les identités, applications et
  affectations actives ;
- le jeu synthétique ne peut pas être réamorcé silencieusement sur les mêmes
  identifiants ;
- la chaîne d'audit reste vérifiable après le retrait.
