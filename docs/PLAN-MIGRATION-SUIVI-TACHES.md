# Migration de N09 – Suivi des tâches

## Phase 1 – Inventaire

- exporter les utilisateurs sans secrets ;
- recenser identifiants, courriels, rôles et affectations de sites ;
- distinguer comptes locaux, comptes NSK et comptes inactifs ;
- figer les règles de correspondance et les doublons.

## Phase 2 – Correspondance et import sans effet

- créer ou retrouver une identité centrale ;
- enregistrer temporairement `legacy_user_id -> identity_id` ;
- importer les rôles `reader` et `writer` avec leur périmètre `site` ;
- n’altérer aucun accès effectif pendant cette phase.

## Phase 3 – Double lecture

- comparer décisions centrale et locale sans modifier les accès ;
- tester séparation des sites, groupes, suspension, révocation et expiration ;
- corriger tout écart puis conserver les preuves de parité ;
- valider les parcours de secours et le retour arrière.

## Phase 4 – Bascule

- faire de l’identifiant central la référence d’identité ;
- conserver `user_id` comme clé métier locale pendant la transition ;
- désactiver la connexion locale en production ;
- basculer les affectations de rôles et de sites vers la source centrale après
  égalité démontrée des décisions.

## Phase 5 – Messagerie

- extraire SMTP et Telegram vers le service de notifications ;
- conserver dans Suivi des tâches les préférences liées aux tâches et sites ;
- émettre des événements idempotents et comparer les journaux.

## Phase 6 – Nettoyage

- invalider les anciennes sessions ;
- retirer secrets, routes et tables devenus inutiles seulement après la période
  de retour arrière convenue ;
- retirer l’identité temporaire de N09 – Énergie ;
- conserver les preuves de migration et le plan de restauration.
