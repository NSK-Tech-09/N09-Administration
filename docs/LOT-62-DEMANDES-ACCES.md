# Lot 62 — Instruction centrale des demandes d’accès

Date : 15 août 2026
Statut : **implémenté, recette Cloud à consigner**

## Objectif

Recevoir les demandes publiques du portail, les conserver dans la source de
vérité Administration et permettre une décision humaine par application sans
créer d’identité ni de privilège implicite.

## Modèle durable

La migration additive `service-node/mariadb/migrations/20260815-access-requests.sql`
ajoute :

- `access_requests` pour les coordonnées minimales, le motif et l’état global ;
- `access_request_lines` pour l’application, la décision, l’identité cible et
  l’affectation éventuellement créée.

Une ligne approuvée référence une affectation centrale réelle. L’affectation,
son audit et la décision de demande sont écrits dans une transaction MariaDB
unique. Une panne annule l’ensemble.

## Frontières de sécurité

- `POST /portal/access-requests` accepte uniquement les origines du portail ;
- aucune comparaison automatique entre le courriel public et une identité NSK ;
- seules les applications actives ouvertes à approbation sont acceptées ;
- `/admin/access-requests` exige `administration:access:decide` ;
- l’opérateur choisit une identité active, un rôle actif, la version exacte du
  catalogue et un périmètre compatible ;
- une justification de 20 à 500 caractères est obligatoire ;
- le refus ne crée aucune affectation ;
- l’audit public conserve une empreinte du courriel, pas le courriel lui-même.

## Retour arrière

La release précédente peut être réactivée sans supprimer les deux tables. Les
demandes déjà reçues restent alors conservées et aucun traitement partiel n’est
simulé. La suppression des tables n’est pas un mécanisme de retour arrière.

## Contrôles automatisés

- flux métier : dépôt, déduplication, approbation atomique et refus ;
- transport HTTP : origine étrangère refusée, dépôt `202`, console protégée ;
- schéma : égalité entre migration et schéma canonique, contraintes et absence
  de secret ;
- non-régression du noyau complet Administration.
