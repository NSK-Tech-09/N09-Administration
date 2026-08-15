# Lot 66 — Connexion par courriel

Date de préparation : 15 août 2026
Statut : **déployé, activé et recetté en production**

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

## Publication GitHub

La PR non brouillon `#78` a été fusionnée le 15 août 2026 après réussite du
workflow « Vérification du noyau » numéro `173`. Le commit publié dans `main`
est `6bb40236dfdfa80a14729c4e708581b3f390694f`.

La publication comprend 16 fichiers, 300 tests Node réussis et 63 tests Python
réussis. Elle n'a appliqué aucune migration, déposé aucun secret et activé
aucun canal en production.

## Activation de production

L'activation a été réalisée le 15 août 2026 dans l'ordre prévu :

1. sauvegarde de `g67ql3_n09_admin_prod` hors dépôt, empreinte SHA-256
   `9f0de15b2fba6b0b76326ef1ca675e60e69a64e6fdf04bec421aa2c9b07f3ea4`,
   avec restauration Infomaniak disponible ;
2. application de `20260815-email-login.sql` avant le nouveau processus ;
3. authentification du domaine `nsktech.fr` dans Brevo, en conservant la
   politique DMARC stricte `p=reject` ;
4. création de l'expéditeur
   `NSK Tech 09 <ne-pas-repondre@nsktech.fr>` et dépôt de la clé API uniquement
   dans l'environnement protégé ; la rotation est attendue avant le
   15 août 2027 ;
5. restriction des appels API à l'unique adresse sortante Infomaniak
   `185.125.27.72` ;
6. installation et activation de la release immuable
   `6bb40236dfdfa80a14729c4e708581b3f390694f` ;
7. redémarrage, santé publique et contrôle des journaux avant ouverture du
   canal ;
8. activation du canal puis recette réelle avec `f.travers@nsktech.fr`.

La clé API, les jetons de connexion et les secrets MariaDB n'ont été ni
affichés, ni copiés dans GitHub, ni intégrés aux archives de release.

## Recette de production

- Administration répond `200` sur `/health` ;
- Suivi des tâches répond `200` sur `/health` ;
- le portail répond `200` et Énergie renvoie la redirection HTTPS attendue ;
- le sélecteur public présente Courriel, Google, Microsoft, GitHub et
  Infomaniak sans imposer un fournisseur unique ;
- Brevo a enregistré l'envoi et la délivrance à 15:07, le clic à 15:09 et
  l'ouverture à 15:10 ;
- la confirmation a créé la session centrale de `Fred TRAVERS` ;
- Administration a reconnu l'identité centrale rattachée ;
- Suivi des tâches a reconnu `Frédéric TRAVERS`, recalculé ses droits et rendu
  les 165 tâches autorisées ;
- l'ancienne adresse IP Brevo provisoire `179.237.88.75` a été retirée ;
- les trois archives de transfert `n09-admin-*.tar.gz` ont été supprimées du
  répertoire `incoming` après contrôle des releases.

La consommation unique, l'expiration et le refus de rejeu restent couvertes
par la suite automatisée. La recette réelle confirme en plus la chaîne
complète émission, livraison, confirmation, session centrale et accès à
l'application pilote.

## Retour arrière

La release précédente
`8d1982b07d46dac6231601b276174a48ba5ffcb0` demeure présente. En cas
d'incident :

1. remettre `N09_EMAIL_LOGIN_ENABLED=false` ;
2. repointer `current` vers cette release puis redémarrer Administration ;
3. contrôler `/health` et les parcours OIDC existants ;
4. révoquer la clé Brevo si l'incident concerne le canal de livraison.

La table ajoutée peut rester en place : elle est inerte lorsque le canal est
fermé, ne donne aucun accès et évite une suppression de données pendant
l'incident.

## Preuves locales

Les tests couvrent configuration fermée, émission, adresse inconnue, remise
échouée, expiration logique, consommation unique, rejeu, sélecteur commun,
session centrale, schéma canonique, migration et transactions MariaDB. Avant
publication, 300 tests Node et 63 tests Python ont réussi dans GitHub Actions.
