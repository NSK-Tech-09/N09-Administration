# ADR-020 — Sessions applicatives révocables

Statut : **proposée, non implémentée et non déployée**

Date : **13 août 2026**

## Contexte

N09 – Administration et N09 – Suivi des tâches utilisent déjà des cookies
`HttpOnly`, `Secure` et `SameSite=Lax`, chiffrés et authentifiés, qui ne passent
ni par une URL ni par le stockage du navigateur. Leur durée absolue est bornée :
huit heures pour Administration et quatre heures pour Suivi des tâches.

Suivi des tâches revérifie en outre le droit central et les conditions locales à
chaque requête protégée. Une révocation de droit ou une suspension devient donc
rapidement opposable et une indisponibilité d’Administration ferme l’accès.

La session elle-même reste toutefois autonome : elle n’est enregistrée dans
aucun registre serveur, aucune expiration après inactivité n’est appliquée et la
déconnexion supprime seulement le cookie du navigateur. Une copie encore valide
du cookie ne peut pas être révoquée individuellement. L’utilisateur ne peut ni
consulter ses sessions actives, ni fermer une session distante.

Cet écart concerne directement `ARC-010`, `ERG-016` et `ERG-032`. Il doit être
résolu sans recopier les secrets d’Infomaniak, sans transformer Administration
en fournisseur de mots de passe et sans affaiblir la vérification des droits à
chaque requête.

## Décision

N09 – Administration devient l’autorité centrale de cycle de vie des sessions
humaines ouvertes dans l’écosystème. L’authentification reste déléguée à
Infomaniak tant que le fournisseur d’identité NSK cible n’est pas disponible.

Une session applicative comporte deux valeurs aléatoires indépendantes :

- un identifiant opaque, sans donnée personnelle, qui sert de référence ;
- un secret imprévisible, connu seulement du navigateur et du serveur de
  l’application, dont seule une empreinte à sens unique est conservée dans le
  registre central.

Le secret brut n’est jamais enregistré en base, dans l’audit, dans un journal,
dans une URL ou dans un stockage JavaScript. Le cookie applicatif reste chiffré,
authentifié, `HttpOnly`, `Secure` et `SameSite=Lax`. Il contient la référence et
le secret de session, ainsi que le minimum nécessaire à l’application.

Le registre central porte au minimum :

- la référence de session, l’empreinte du secret, l’identité et l’application ;
- la création, la dernière activité confirmée, l’échéance d’inactivité et
  l’échéance absolue ;
- l’instant de la dernière authentification ou réauthentification ;
- la révocation éventuelle, son auteur, sa cause et la version de l’état ;
- une description bornée et compréhensible du contexte, sans empreinte globale
  de l’appareil.

La création, le renouvellement, l’expiration et la révocation produisent un
événement dans le journal d’audit central. La mutation du registre et son
événement sont atomiques. Les secrets, l’empreinte complète et les identifiants
complets de session sont exclus de l’audit.

## Ouverture et contrôle d’une session

Pour Administration, le retour OIDC Infomaniak validé crée directement la
session centrale avant d’émettre le cookie.

Pour une application, l’échange serveur à serveur du code de connexion crée la
session centrale et remet une seule fois sa référence et son secret à
l’application authentifiée. L’application les enferme immédiatement dans son
propre cookie. Aucun cookie n’est partagé entre domaines et aucune preuve
Infomaniak n’est transmise à l’application.

Chaque requête protégée doit ensuite satisfaire simultanément :

1. l’ouverture cryptographique du cookie local ;
2. l’existence d’une session centrale active correspondant à l’application et
   à l’identité ;
3. la concordance de l’empreinte du secret en temps constant ;
4. les échéances absolue et d’inactivité appliquées côté serveur ;
5. l’identité active, le droit central, le périmètre et les conditions locales.

Suivi des tâches transmet la preuve de session dans le même appel interne signé
qui demande déjà la décision centrale. Le contrôle de session ne remplace donc
aucun contrôle d’autorisation. Une réponse absente, ambiguë, expirée ou révoquée
ferme l’accès.

La dernière activité peut être consolidée à fréquence bornée afin d’éviter une
écriture à chaque lecture, mais l’échéance d’inactivité reste calculée et
appliquée par le serveur. Une prolongation ne peut jamais dépasser l’échéance
absolue. Une réauthentification ou un changement de privilège renouvelle la
session et invalide son ancien secret.

Les valeurs initiales proposées pour la préproduction sont :

| Application | Inactivité | Durée absolue |
|---|---:|---:|
| N09 – Administration | 30 minutes | 8 heures |
| N09 – Suivi des tâches | 60 minutes | 4 heures |

Ces valeurs sont configurables par application sous un plafond central. Leur
modification est une décision de sécurité documentée, pas un réglage libre de
l’utilisateur.

## Déconnexion et révocation

Une déconnexion ordinaire révoque d’abord la session dans le registre central,
puis efface le cookie. L’interface ne présente le succès qu’après confirmation
du serveur.

Si Administration est momentanément indisponible, l’application :

- refuse déjà les nouvelles requêtes protégées ;
- inscrit localement la référence dans une liste de refus et une file de
  révocation persistante, sans conserver le secret ;
- efface le cookie et indique que la fermeture centrale est en cours ;
- rejoue la révocation avec son identité technique jusqu’à confirmation.

Une application ne peut révoquer que les sessions qu’elle a ouvertes. La liste
locale est supprimée seulement après confirmation centrale ou après l’échéance
absolue de la session.

L’utilisateur peut consulter ses propres sessions et révoquer une autre
session ou toutes les autres sessions. La session actuelle est explicitement
signalée ; sa révocation provoque une déconnexion immédiate.

Un opérateur habilité utilise la permission distincte
`administration:sessions:revoke`. Il ne peut agir que dans son périmètre, doit
fournir une justification et ne bénéficie d’aucun contournement générique lié
à un rôle administrateur. La suspension d’une identité révoque toutes ses
sessions actives dans la même opération gouvernée.

## Espace personnel

L’espace personnel central présente uniquement des informations utiles et
compréhensibles : application, date de création, dernière activité, état,
navigateur ou catégorie d’appareil et caractère actuel de la session. Une
localisation réseau, si elle est un jour ajoutée, reste approximative,
facultative et ne constitue jamais une preuve d’identité.

Les rôles et périmètres restent consultables sans être modifiables depuis cet
espace. La gestion des facteurs et de la récupération demeure chez le
fournisseur d’identité ; Administration ne copie ni mot de passe, ni facteur,
ni code de récupération. Les actions sensibles nécessitant une
réauthentification récente seront introduites dans un lot distinct.

Chaque application conserve une destination de retour validée par une liste
d’origines autorisées. L’avertissement avant expiration, la protection des
brouillons et la convergence entre onglets font partie de la recette de chaque
interface avant son passage en production.

## Schéma et compatibilité

Le premier lot crée une table additive `application_sessions`. Les événements
de cycle de vie rejoignent le journal d’audit existant ; aucune seconde source
d’audit n’est créée.

Les anciens cookies autonomes sont tolérés uniquement pendant une fenêtre de
migration datée et mesurée. Ils ne peuvent pas être inscrits silencieusement
comme sessions de confiance. À la fin de la fenêtre, la rotation du but
cryptographique ou de la clé de session les invalide et impose une nouvelle
connexion.

La suppression du courtier transitoire décrite par `ADR-010` ne supprime pas le
registre : un futur fournisseur OIDC NSK devra créer ou renouveler les mêmes
sessions centrales par un contrat standard équivalent.

## Déploiement progressif

1. Ajouter le registre et l’audit, sans modifier les cookies actifs.
2. Créer les nouvelles sessions en observation et comparer les décisions sans
   les rendre opposables.
3. Rendre le registre opposable dans Suivi des tâches, application pilote, avec
   retour arrière vers la release précédente.
4. Rendre le registre opposable dans Administration.
5. Fermer la fenêtre des anciens cookies et imposer une reconnexion.
6. Ouvrir la consultation et la révocation de ses propres sessions.
7. Ouvrir la révocation opérateur après attribution gouvernée de la permission
   dédiée.

Chaque étape exige une sauvegarde vérifiée, une migration additive, une release
immuable, une recette serveur et un retour arrière documenté. Aucun lot ne doit
activer simultanément la gestion des facteurs d’authentification.

## Validation obligatoire

Les tests automatisés doivent couvrir au minimum :

- absence de session, secret erroné, session inconnue, expirée ou révoquée ;
- échéance absolue et échéance d’inactivité contrôlées côté serveur ;
- rotation après réauthentification et invalidation de l’ancien secret ;
- révocation de la session actuelle, d’une autre session et de toutes les
  autres sessions ;
- suspension d’une identité et modification de droits pendant une session ;
- isolation entre identités, applications et périmètres ;
- refus de la révocation opérateur sans permission, hors périmètre ou sans
  justification ;
- indisponibilité centrale, liste de refus locale et rejeu de révocation ;
- audit attendu sans secret, cookie, empreinte complète ni identifiant complet ;
- avertissement d’expiration, conservation d’un brouillon et cohérence entre
  onglets.

La recette ne peut pas se limiter à l’absence d’un bouton dans l’interface :
les refus doivent être prouvés sur les routes serveur et l’absence de mutation
doit être vérifiée.

## Conséquences

- une copie de cookie peut être révoquée avant son expiration ;
- la déconnexion devient une invalidation serveur vérifiable ;
- l’utilisateur gagne une autonomie lisible sur ses sessions ;
- la suspension et les changements critiques de droits ont un effet cohérent
  dans tout l’écosystème ;
- Administration porte un registre sensible supplémentaire, avec des écritures
  d’activité bornées et une exigence forte de disponibilité ;
- les applications conservent leurs sessions propres et leurs contrôles métier,
  sans partager de secret ni de cookie.

## Références

- `ADR-003-IDENTITES-FEDEREES.md`
- `ADR-010-COURTAGE-CONNEXION-APPLICATIVE.md`
- `ADR-013-REVOCATION-CENTRALE-ACCES.md`
- `ARC-008`
- `ARC-009`
- `ARC-010`
- `ARC-013`
- `ERG-016`
- `ERG-032`
- `TST-001`
