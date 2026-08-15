# Lot 66 — Connexion par courriel

Date de préparation : 15 août 2026
Statut : **implémenté et validé localement ; non publié et non déployé**

## Objectif

Rendre opérationnelle l'option « Courriel » annoncée au lot 65, sans imposer
de compte fournisseur et sans créer une seconde identité pour la même
personne.

## Réalisation

- sélecteur de connexion NSK commun au portail, aux applications et à
  l'espace « Mon compte » ;
- formulaire de demande accessible au clavier, mobile et aux quatre thèmes ;
- recherche limitée aux identités centrales actives ;
- réponse publique neutre pour empêcher la divulgation de l'existence d'un
  compte ;
- lien aléatoire à usage unique, valable dix minutes ;
- empreinte seule en mémoire et dans MariaDB ;
- consommation atomique, auditée et résistante au rejeu ;
- confirmation volontaire avant consommation afin qu'un robot de messagerie
  ne neutralise pas le lien ;
- invalidation auditée en cas d'échec d'envoi ;
- session centrale identique aux autres méthodes, portant seulement
  `providerKey=email` comme origine de preuve ;
- adaptateur de livraison Brevo sans dépendance logicielle ajoutée ;
- variables d'environnement documentées, canal désactivé par défaut.

## Variables protégées

L'activation exige :

- `N09_EMAIL_LOGIN_ENABLED=true` ;
- `N09_EMAIL_LOGIN_DELIVERY_PROVIDER=brevo` ;
- `N09_EMAIL_LOGIN_SENDER_EMAIL` ;
- `N09_EMAIL_LOGIN_SENDER_NAME` ;
- `N09_EMAIL_LOGIN_BREVO_API_KEY` ;
- `N09_PUBLIC_ORIGIN`, origine HTTPS exacte d'Administration.

Aucune valeur réelle ne doit entrer dans GitHub, une release, un journal ou
une sauvegarde documentaire.

## Publication et activation restantes

1. publier le code par PR non brouillon et attendre tous les contrôles verts ;
2. sauvegarder la base de production et vérifier la restauration disponible ;
3. appliquer `20260815-email-login.sql` avant le nouveau processus ;
4. créer ou sélectionner l'expéditeur Brevo autorisé et déposer la clé dans
   l'environnement protégé ;
5. installer une release immuable puis redémarrer Administration ;
6. vérifier la santé avec le canal encore fermé ;
7. vérifier que le frontal ne journalise pas la chaîne de requête de
   `/auth/email/confirm` ;
8. activer le canal et réaliser une recette réelle avec
   `f.travers@nsktech.fr` ;
9. contrôler réception, confirmation, consommation unique, retour
   Portail/Tâches/Énergie,
   révocation de session et absence de secret dans les journaux ;
10. documenter les preuves et conserver la release précédente pour repli.

Le retour arrière applicatif remet le canal à `false` et réactive la release
précédente. La table ajoutée peut rester en place : elle est inerte, ne donne
aucun accès et évite une suppression de données pendant l'incident.

## Preuves locales

Les tests couvrent configuration fermée, émission, adresse inconnue, remise
échouée, expiration logique, consommation unique, rejeu, sélecteur commun,
session centrale, schéma canonique, migration et transactions MariaDB. La
suite complète du dépôt doit être rejouée juste avant publication.
