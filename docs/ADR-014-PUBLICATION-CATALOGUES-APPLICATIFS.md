# ADR-014 – Publier les catalogues applicatifs et les prérequis de provisionnement

Statut : **Accepté pour la préproduction**
Date : **10 août 2026**

## Contexte

Administration sait enregistrer les applications et leurs affectations, mais ne
conservait pas encore la définition versionnée des rôles qu’elles reconnaissent.
Ouvrir les octrois dans cet état permettrait de choisir un rôle fictif ou de
créer un accès central inutilisable faute de profil métier cohérent.

## Décision

Chaque application publie, avec sa propre identité technique, un instantané
comprenant rôles, permissions, types de périmètres et prérequis de
provisionnement. Les identifiants sont stables, les états `active`, `planned` et
`deprecated` sont explicites et toute version nouvelle est auditée.

Administration vérifie la cohérence structurelle et la compatibilité avec les
affectations actives. Elle conserve l’historique et présente la dernière version
dans le registre en lecture seule. Elle n’interprète ni ne crée les objets
métier décrits par les prérequis.

N09 – Suivi des tâches déclare un profil local préexistant, lié par
`identity_id`, avec rôle et appartenances de sites confirmés par l’application.
Le courriel ne sert jamais de clé de rapprochement et aucune création
automatique n’est activée.

## Conséquences

- une application ne peut publier que son propre vocabulaire ;
- une version ne peut pas être remplacée silencieusement ;
- un identifiant publié n’est pas supprimé sans migration explicite ;
- un catalogue ne peut pas rendre une affectation active ininterprétable ;
- la publication ne crée, ne modifie et ne révoque aucune affectation ;
- les octrois centraux restent fermés jusqu’à l’existence d’un parcours de
  provisionnement contrôlé et testé.

## Retour arrière

La table de versions et la route de publication peuvent rester inutilisées sans
modifier les décisions actuelles. Les catalogues sont additifs et la production
de Suivi des tâches demeure inchangée.
