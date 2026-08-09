# ADR-002 – Stockage transactionnel et audit append-only

Statut : **Acceptée**  
Date : **9 août 2026**

## Contexte

Le noyau doit conserver identités, applications et affectations sans dissocier
une modification sensible de sa preuve. Le stockage cible de production n’est
pas encore arrêté et le projet doit rester exécutable localement sans service
externe ni secret.

## Décision

Le premier stockage persistant utilise SQLite par la bibliothèque standard
Python. Chaque écriture métier et son événement d’audit appartiennent à la même
transaction. Le journal est append-only : des déclencheurs refusent toute mise à
jour ou suppression, et un chaînage SHA-256 permet d’en vérifier l’intégrité.

Le moteur SQLite est un adaptateur remplaçable. Le contrat métier ne dépend pas
de ses types propres et pourra être porté vers PostgreSQL lorsque les exigences
d’exploitation le justifieront.

## Conséquences

- installation locale sans dépendance ni service supplémentaire ;
- tests transactionnels rapides et déterministes ;
- altération accidentelle ou directe du journal bloquée ou détectable ;
- SQLite ne constitue pas encore la stratégie de haute disponibilité ;
- sauvegarde, archivage externe, rétention et séparation opérationnelle des
  droits restent nécessaires avant une exploitation réelle.

## Options envisagées

- PostgreSQL immédiatement : robuste mais prématuré pour un noyau sans service ;
- fichiers JSON : rejetés faute de transactions et de contrôle de concurrence ;
- service d’audit séparé immédiat : reporté jusqu’à la définition de
  l’architecture de déploiement.

## Références

- `ARC-013`, `ARC-014`, `DEV-003`, `TST-003`, `REL-002`.
