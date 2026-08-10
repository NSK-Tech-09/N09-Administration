# ADR-010 — Courtage transitoire de connexion applicative

## Statut

Accepté pour la préproduction du moteur Node de N09 – Suivi des tâches.

## Décision

N09 – Administration fournit temporairement le point de courtage entre la session
Infomaniak déjà vérifiée et l’application pilote. Il ne partage aucun cookie avec
l’application et ne lui transmet aucune preuve Infomaniak.

Le parcours reprend les propriétés d’Authorization Code avec PKCE :

1. l’application crée `state`, vérificateur et défi PKCE ;
2. Administration vérifie sa propre session, l’identité NSK active, l’application,
   l’adresse de retour enregistrée et la permission `tasks:read` ;
3. un code aléatoire valable 90 secondes est conservé uniquement sous forme
   d’empreinte et lié à l’identité, l’application, l’adresse et au défi PKCE ;
4. l’application échange ce code côté serveur avec son identité technique HMAC ;
5. l’échange atomique consomme le code et est audité ;
6. l’application n’ouvre sa session locale que si `identity_id` correspond déjà à
   un utilisateur local.

Aucune création ni liaison par adresse électronique n’est automatique. Les droits
par site et rôles métier restent locaux. La permission centrale d’entrée est
revérifiée pour chaque appel protégé ; une panne centrale ferme l’accès.

## Limite assumée et sortie

Ce courtier n’est pas le fournisseur d’identité cible. Lorsque `auth.nsktech.fr`
sera disponible, l’application adoptera son endpoint OIDC standard et
Administration conservera seulement le registre, les affectations et l’audit. La
suppression du courtier exigera une recette équivalente sur l’émetteur, l’audience,
PKCE, le rejeu, la révocation et le retour arrière.

## Retour arrière

Le déploiement de l’application peut revenir au moteur précédent sans toucher à la
production actuelle. Les nouvelles tables ne donnent aucun droit par elles-mêmes ;
révoquer l’adresse de retour ou arrêter le nouveau moteur ferme le parcours.
