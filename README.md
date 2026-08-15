# N09 – Administration

Poste de contrôle central des identités, des accès et de l’audit de l’écosystème
NSK Tech 09.

## Mission

N09 – Administration répond à quatre questions :

1. Qui est cette personne ou ce service ?
2. À quelles applications peut-il accéder ?
3. Dans quelles limites et jusqu’à quand ?
4. Qui a décidé, pourquoi et quand ?

Le module ne devient pas propriétaire des données métier des applications. Les
applications publient leur catalogue de rôles, permissions et types de
périmètres ; Administration conserve les affectations centrales, tandis que
chaque application reste seule responsable de l’interprétation et du contrôle
serveur de ses règles métier.

## Principes non négociables

- refus par défaut et privilège minimal ;
- identité technique immuable, distincte de l’adresse électronique ;
- aucune auto-attribution de droit ;
- décision serveur, jamais fondée sur l’interface seule ;
- révocation et expiration explicites ;
- traçabilité de toute décision sensible ;
- secrets hors du code et des journaux ;
- migration progressive et réversible ;
- accessibilité et vocabulaire compréhensible ;
- séparation entre identité, accès applicatif et droit métier ;
- aucun privilège métier implicite pour un super-administrateur technique.

## État

Le noyau contient le modèle de domaine, la décision d’accès, un stockage SQLite
transactionnel, un journal d’audit append-only vérifiable, les groupes, les
délégations bornées, les demandes d’accès par application et le cycle audité de
rattachement d’une identité externe. Une connexion inconnue crée uniquement une
demande temporaire : son approbation explicite établit le lien d’identité sans
créer aucun droit applicatif. Il ne gère aucun mot de passe externe.

La première frontière d’API interne permet déjà d’évaluer un accès sans partager
la base avec les applications. Un transport HTTP fermé par défaut est validé en
local : sans adaptateur d'authentification, toute décision est refusée. Le
service Node et son adaptateur Infomaniak OIDC sont déployés en
préproduction. L'adaptateur réalise Authorization Code avec PKCE, vérifie la
signature RS256 et les claims obligatoires, puis crée seulement une session de
preuve à rattacher : aucun compte ni droit NSK n'est créé automatiquement.

Une interface authentifiée permet de traiter les demandes de rattachement. Elle
exige la permission centrale exacte `administration:identity-links:decide`, une
preuve CSRF et une justification auditée. L'approbation relie une preuve externe
à une identité NSK active, sans créer de rôle ni de droit applicatif.

Un tableau de bord distinct présente en lecture seule les identités,
applications et affectations centrales. Il exige la permission exacte
`administration:access:read` et n'expose aucune action de création, modification
ou révocation. Le pouvoir de consulter le registre ne se confond donc jamais
avec celui de décider un rattachement ou un droit.

Une frontière séparée porte les décisions d'accès opérationnelles. Elle exige
`administration:access:decide` et permet soit de révoquer une affectation active
avec contrôle de version, soit d'accorder uniquement un rôle actif du dernier
catalogue publié. L'octroi fixe exactement la personne, le rôle et le périmètre,
exige une justification et reprend comme conditions toutes les confirmations
applicatives publiées. Le pouvoir de décision lui-même reste soustrait à cette
interface générale.

Les objets synthétiques ayant servi à la validation initiale disposent d'une
procédure de retrait dédiée : l'affectation est révoquée, l'identité archivée et
l'application retirée. Leur histoire reste visible et auditée ; ils ne comptent
plus parmi les accès actifs.

Les objets de gouvernance sont conservés dans la même frontière transactionnelle
que leur événement d’audit : une mutation sans preuve valide est annulée.

Une application authentifiée peut maintenant publier son catalogue versionné de
rôles, permissions, types de périmètres et prérequis de provisionnement. Une
version nouvelle est immuable et auditée ; la répétition identique est
idempotente. La console les présente en lecture seule et signale explicitement
une application sans catalogue. Cette publication n’ouvre aucun octroi.

Le contrat local de réception des notifications est également prêt. Une
application authentifiée remet des événements métier bornés dans une boîte
centrale durable et auditée. La répétition identique est idempotente, un conflit
de contenu est refusé, les échecs sont repris sous bail puis mis en quarantaine.
Aucun canal externe ni secret de messagerie n'est activé par ce lot.

La matérialisation centrale est maintenant validée localement. Administration
demande à l’application émettrice une résolution métier signée, crée le centre
interne idempotent et conserve les demandes de canaux externes dans l’état
`blocked`. Une interface personnelle expose le compteur et les états lu/non lu,
sans suppression ni action sensible ; voir
`docs/ADR-017-MATERIALISATION-CENTRE-NOTIFICATIONS.md`.

Une console d’exploitation gouvernée est également prête localement. Elle rend
visibles la file, les reprises, les quarantaines, les motifs de suppression et
le blocage des canaux externes sans imposer un accès MariaDB. Sa permission est
distincte des autres pouvoirs centraux et la page ne contient aucune action de
traitement ; voir `docs/ADR-018-OBSERVABILITE-NOTIFICATIONS.md`.

Le traitement interne peut désormais être ordonnancé par un planificateur
standard. Chaque invocation reste ponctuelle, refuse tout environnement autre
que la préproduction, exige la fermeture explicite des canaux externes et prend
un verrou singleton dans MariaDB. La console conserve seulement l’état borné du
dernier cycle, sans charge métier ni identité technique ; voir
`docs/ADR-019-TRAITEMENT-AUTONOME-NOTIFICATIONS.md`.

Le registre de sessions a franchi l'observation inopposable et prépare désormais
son opposabilité progressive. Le lot 47 couvre l'application pilote Suivi des
tâches ; le lot 48 rend la propre session web d'Administration contrôlable et
révocable côté serveur, tout en conservant `observe` jusqu'à une bascule
explicitement recettée. Une déconnexion opposable ne présente le succès qu'après
révocation centrale confirmée ; voir
`docs/LOT-48-OPPOSABILITE-SESSIONS-ADMINISTRATION.md`.

Le lot 49 fixe le déploiement conjoint sur Infomaniak : état initial réel,
commits canoniques, sauvegardes, migration additive de la file de révocation,
releases immuables, paliers `issue` puis `enforce`, recettes et retours arrière
sans suppression de preuve ; voir
`docs/LOT-49-DEPLOIEMENT-SESSIONS-OPPOSABLES-PREPROD.md`.

Le lot 50 a fermé en préproduction la compatibilité avec les anciens cookies : format
versionné obligatoire, disparition de l'ancien champ et des anciens réglages,
preuve centrale obligatoire dans les deux applications et retour arrière sans
résurrection. Son déploiement a imposé une nouvelle connexion en préproduction ;
voir `docs/LOT-50-FERMETURE-ANCIENNES-SESSIONS-PREPROD.md`.

Le lot 51 a ouvert et recetté en préproduction l'espace personnel « Mes sessions » dans
Administration : consultation limitée à sa propre identité, identification de
la session courante, fermeture distante unitaire ou fermeture atomique de toutes
les autres sessions actives. Les cibles sont scellées, les mutations protégées
contre la falsification et chaque fermeture est auditée ; voir
`docs/LOT-51-GESTION-PERSONNELLE-SESSIONS.md`.

Les sept étapes de l’ADR-020 sont désormais recettées en préproduction. Le lot 53
a ouvert la révocation opérateur protégée par la permission distincte
`administration:sessions:revoke`, sans secret ni identifiant technique affiché,
avec cible scellée, justification, contrôle de version et audit atomique ; voir
`docs/LOT-53-REVOCATION-OPERATEUR-SESSIONS.md`.

Le lot 54 ferme en préproduction la dette de cohérence restante : une suspension
gouvernée passe l’identité à `suspended` et révoque toutes ses sessions actives
dans une transaction unique. Le pouvoir `administration:identities:suspend`, la
cible scellée, l’interdiction de l’auto-suspension et le rollback concurrent sont
séparés des autres responsabilités ; voir
`docs/LOT-54-SUSPENSION-ATOMIQUE-IDENTITES.md`.

Le lot 55 complète en préproduction ce cycle sans ressusciter le passé : une identité
suspendue peut être réactivée par le pouvoir distinct
`administration:identities:reactivate`, mais aucune session révoquée ou expirée
n’est restaurée. La transition est atomique, auditée, refusée si une session
active subsiste et impose une nouvelle authentification ; voir
`docs/LOT-55-REACTIVATION-GOUVERNEE-IDENTITES.md`.

Le lot 56 déploie en préproduction la sortie définitive sans effacement de mémoire :
une identité active ou suspendue peut être désactivée par le pouvoir distinct
`administration:identities:disable`. La même transaction passe l’identité à
`disabled`, révoque toutes ses sessions et toutes ses affectations actives, puis
audite chaque transition avec une corrélation commune. L’auto-désactivation et
la désactivation directe d’une autre autorité de désactivation sont refusées.
La recette réelle sur une identité jetable confirme l’état `disabled`, la
révocation de son affectation temporaire et la validité de l’audit ; voir
`docs/LOT-56-DESACTIVATION-GOUVERNEE-IDENTITES.md`.

Le lot 57 prépare le passage à la production sans l’ouvrir implicitement. Un
contrat scellé vérifie les deux artefacts immuables Administration et Suivi des
tâches, leurs tests, les sauvegardes restaurées, les releases de repli, les
cibles isolées et la fenêtre de changement. Il refuse tout secret, toute marque
de préproduction, tout canal externe ouvert et toute modification de N09 –
Énergie ; voir `docs/LOT-57-CONTRAT-PROMOTION-PRODUCTION.md`.

Le lot 60 étend l’autorité de session centrale à N09 – Énergie et en consigne
la recette de production réelle : connexion, autorisations, révocation,
reconnexion, contrôles de sécurité, versions déployées et retours arrière. Il
confirme également que l’ancien hébergement ne peut pas encore être résilié
tant que le portail, les anciens noms publics et les archives historiques n’en
sont pas sortis ; voir `docs/LOT-60-ENERGIE-PRODUCTION.md`.

Le lot 61 raccorde le portail public à l'autorité centrale sans lui attribuer
un nouvel environnement Node.js : Administration émet une session chiffrée
limitée à l'audience `n09-portail`, filtre le catalogue d'après les
affectations centrales actives et confirme la révocation à la déconnexion ;
voir `docs/LOT-61-PORTAIL-CLOUD.md`.

Le lot 62 active les demandes d’accès publiques : réception bornée depuis le
portail, décision humaine par application, affectation atomique fondée sur le
catalogue publié et audit sans privilège implicite ; voir
`docs/LOT-62-DEMANDES-ACCES.md`.

Le lot 65 rétablit une porte d'entrée entièrement NSK avant toute délégation
d'authentification. Infomaniak reste disponible sans être présenté comme
l'identité NSK elle-même ; Google, Microsoft, GitHub, le courriel sans mot de
passe puis les clés d'accès suivent une trajectoire explicite et sans droit
implicite ; voir `docs/LOT-65-CONNEXION-NSK-MULTIFOURNISSEURS.md`.

Le lot 66 matérialise la première alternative universelle : un lien de
connexion par courriel, éphémère et à usage unique, utilisable uniquement par
une identité NSK déjà active. Le secret brut n'entre ni dans MariaDB ni dans
l'audit ; un échec de remise invalide le lien. Tous les accès — portail,
applications et espace personnel — passent désormais par le même sélecteur ;
voir `docs/ADR-022-CONNEXION-COURRIEL-SANS-MOT-DE-PASSE.md` et
`docs/LOT-66-CONNEXION-COURRIEL.md`.

## Prérequis et démarrage local

- Python 3.11 ou supérieur ;
- aucune dépendance applicative externe pour le noyau actuel.

Le stockage de test fonctionne en mémoire. Pour un stockage local persistant,
utiliser un chemin propre à l’environnement sur le modèle de `.env.example`.

## Vérification

```powershell
python -m unittest discover -s tests -v
node --test "service-node/*.test.mjs"
```

La même vérification est exécutée automatiquement à chaque PR et mise à jour de
`main`. Le dépôt public utilise les minutes Actions non facturées par GitHub.

Le service Node dispose de points d'entrée explicites pour son écoute locale
fermée, l'amorçage synthétique de la préproduction et le parcours OIDC. Les
variables attendues sont décrites dans `service-node/.env.example` ; ce fichier
ne contient aucun secret réel. La production reste inchangée.

## Documents

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/CONTRAT-IDENTITE-ACCES.md`](docs/CONTRAT-IDENTITE-ACCES.md)
- [`docs/PLAN-MIGRATION-SUIVI-TACHES.md`](docs/PLAN-MIGRATION-SUIVI-TACHES.md)
- [`docs/ADR-001-SEPARATION-RESPONSABILITES.md`](docs/ADR-001-SEPARATION-RESPONSABILITES.md)
- [`docs/ADR-002-STOCKAGE-ET-AUDIT.md`](docs/ADR-002-STOCKAGE-ET-AUDIT.md)
- [`docs/ADR-004-PORTAGE-SERVICE-NODE.md`](docs/ADR-004-PORTAGE-SERVICE-NODE.md)
- [`docs/ADR-005-MARIADB-PRODUCTION.md`](docs/ADR-005-MARIADB-PRODUCTION.md)
- [`docs/ADR-006-TRANSPORT-HTTP.md`](docs/ADR-006-TRANSPORT-HTTP.md)
- [`docs/ADR-007-DEMANDES-RATTACHEMENT-NODE.md`](docs/ADR-007-DEMANDES-RATTACHEMENT-NODE.md)
- [`docs/ADR-008-ADMINISTRATION-RATTACHEMENTS.md`](docs/ADR-008-ADMINISTRATION-RATTACHEMENTS.md)
- [`docs/LOT-52-IDENTITE-HUMAINE-RECETTE.md`](docs/LOT-52-IDENTITE-HUMAINE-RECETTE.md)
- [`docs/ADR-009-APPLICATION-PILOTE-SUIVI-TACHES.md`](docs/ADR-009-APPLICATION-PILOTE-SUIVI-TACHES.md)
- [`docs/ADR-010-COURTAGE-CONNEXION-APPLICATIVE.md`](docs/ADR-010-COURTAGE-CONNEXION-APPLICATIVE.md)
- [`docs/ADR-011-CONSULTATION-CENTRALE-ACCES.md`](docs/ADR-011-CONSULTATION-CENTRALE-ACCES.md)
- [`docs/ADR-012-RETRAIT-DONNEES-SYNTHETIQUES.md`](docs/ADR-012-RETRAIT-DONNEES-SYNTHETIQUES.md)
- [`docs/ADR-013-REVOCATION-CENTRALE-ACCES.md`](docs/ADR-013-REVOCATION-CENTRALE-ACCES.md)
- [`docs/ADR-014-PUBLICATION-CATALOGUES-APPLICATIFS.md`](docs/ADR-014-PUBLICATION-CATALOGUES-APPLICATIFS.md)
- [`docs/ADR-015-OCTROIS-APPLICATIFS-GOUVERNES.md`](docs/ADR-015-OCTROIS-APPLICATIFS-GOUVERNES.md)
- [`docs/ADR-016-RECEPTION-CENTRALE-NOTIFICATIONS.md`](docs/ADR-016-RECEPTION-CENTRALE-NOTIFICATIONS.md)
- [`docs/ADR-017-MATERIALISATION-CENTRE-NOTIFICATIONS.md`](docs/ADR-017-MATERIALISATION-CENTRE-NOTIFICATIONS.md)
- [`docs/ADR-018-OBSERVABILITE-NOTIFICATIONS.md`](docs/ADR-018-OBSERVABILITE-NOTIFICATIONS.md)
- [`docs/ADR-019-TRAITEMENT-AUTONOME-NOTIFICATIONS.md`](docs/ADR-019-TRAITEMENT-AUTONOME-NOTIFICATIONS.md)
- [`docs/ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`](docs/ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md)
- [`docs/ADR-021-SESSIONS-MULTI-APPLICATIONS.md`](docs/ADR-021-SESSIONS-MULTI-APPLICATIONS.md)
- [`docs/ADR-022-CONNEXION-COURRIEL-SANS-MOT-DE-PASSE.md`](docs/ADR-022-CONNEXION-COURRIEL-SANS-MOT-DE-PASSE.md)
- [`docs/LOT-45-OBSERVATION-INOPPOSABLE-SESSIONS.md`](docs/LOT-45-OBSERVATION-INOPPOSABLE-SESSIONS.md)
- [`docs/LOT-46-ACTIVATION-OBSERVATION-SESSIONS-PREPROD.md`](docs/LOT-46-ACTIVATION-OBSERVATION-SESSIONS-PREPROD.md)
- [`docs/LOT-47-OPPOSABILITE-SESSIONS-SUIVI-TACHES.md`](docs/LOT-47-OPPOSABILITE-SESSIONS-SUIVI-TACHES.md)
- [`docs/LOT-48-OPPOSABILITE-SESSIONS-ADMINISTRATION.md`](docs/LOT-48-OPPOSABILITE-SESSIONS-ADMINISTRATION.md)
- [`docs/LOT-49-DEPLOIEMENT-SESSIONS-OPPOSABLES-PREPROD.md`](docs/LOT-49-DEPLOIEMENT-SESSIONS-OPPOSABLES-PREPROD.md)
- [`docs/LOT-50-FERMETURE-ANCIENNES-SESSIONS-PREPROD.md`](docs/LOT-50-FERMETURE-ANCIENNES-SESSIONS-PREPROD.md)
- [`docs/LOT-51-GESTION-PERSONNELLE-SESSIONS.md`](docs/LOT-51-GESTION-PERSONNELLE-SESSIONS.md)
- [`docs/LOT-53-REVOCATION-OPERATEUR-SESSIONS.md`](docs/LOT-53-REVOCATION-OPERATEUR-SESSIONS.md)
- [`docs/LOT-54-SUSPENSION-ATOMIQUE-IDENTITES.md`](docs/LOT-54-SUSPENSION-ATOMIQUE-IDENTITES.md)
- [`docs/LOT-55-REACTIVATION-GOUVERNEE-IDENTITES.md`](docs/LOT-55-REACTIVATION-GOUVERNEE-IDENTITES.md)
- [`docs/LOT-56-DESACTIVATION-GOUVERNEE-IDENTITES.md`](docs/LOT-56-DESACTIVATION-GOUVERNEE-IDENTITES.md)
- [`docs/LOT-57-CONTRAT-PROMOTION-PRODUCTION.md`](docs/LOT-57-CONTRAT-PROMOTION-PRODUCTION.md)
- [`docs/LOT-60-ENERGIE-PRODUCTION.md`](docs/LOT-60-ENERGIE-PRODUCTION.md)
- [`docs/LOT-61-PORTAIL-CLOUD.md`](docs/LOT-61-PORTAIL-CLOUD.md)
- [`docs/LOT-62-DEMANDES-ACCES.md`](docs/LOT-62-DEMANDES-ACCES.md)
- [`docs/LOT-63-CONFORMITE-ET-RETOUR-COMPTE.md`](docs/LOT-63-CONFORMITE-ET-RETOUR-COMPTE.md)
- [`docs/LOT-65-CONNEXION-NSK-MULTIFOURNISSEURS.md`](docs/LOT-65-CONNEXION-NSK-MULTIFOURNISSEURS.md)
- [`docs/LOT-66-CONNEXION-COURRIEL.md`](docs/LOT-66-CONNEXION-COURRIEL.md)
- [`docs/ETAT-PREPROD-INFOMANIAK.md`](docs/ETAT-PREPROD-INFOMANIAK.md)
- [`docs/CONFORMITE-NSES.md`](docs/CONFORMITE-NSES.md)
- [`docs/CONTRAT-API-INTERNE.md`](docs/CONTRAT-API-INTERNE.md)
