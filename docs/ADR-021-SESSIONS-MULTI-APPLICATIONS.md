# ADR-021 – Registre central de sessions multi-applications

## Décision

N09 – Administration émet, contrôle et révoque une preuve de session distincte
pour chaque application enregistrée. Une preuve délivrée pour N09 – Énergie ne
peut jamais être présentée à N09 – Suivi des tâches, et réciproquement.

Le routage repose exclusivement sur l'identifiant applicatif central. Chaque
application conserve sa politique d'activation et ses durées propres. Le mode
de N09 – Énergie est borné à la production et reste désactivé par défaut.

## Motivation

Le courtage de connexion et la décision d'accès étaient déjà multi-applications,
mais l'autorité de session ne délivrait jusque-là une preuve opposable qu'au
pilote N09 – Suivi des tâches. Étendre le registre évite une exception locale
pour Énergie et maintient une authentification centralisée, révocable et
auditée.

## Garde-fous

- aucun cookie n'est partagé entre sous-domaines ;
- les secrets techniques et les secrets de session restent indépendants ;
- l'application, l'identité et la preuve doivent correspondre exactement ;
- une application inconnue ne reçoit aucune preuve ;
- l'activation de N09 – Énergie exige explicitement
  `N09_ENERGY_SESSION_MODE=enforce` en production ;
- le retour arrière consiste à remettre ce mode à `disabled` sans altérer les
  sessions de Suivi des tâches.
