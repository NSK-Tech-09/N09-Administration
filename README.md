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

Une frontière séparée prépare la première décision d'accès opérationnelle : la
révocation justifiée d'une affectation active. Elle exige
`administration:access:decide`, contrôle la version de l'affectation, soustrait
le pouvoir de décision lui-même à cette interface générale et ne permet encore
aucun octroi arbitraire.

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

## Prérequis et démarrage local

- Python 3.11 ou supérieur ;
- aucune dépendance applicative externe pour le noyau actuel.

Le stockage de test fonctionne en mémoire. Pour un stockage local persistant,
utiliser un chemin propre à l’environnement sur le modèle de `.env.example`.

## Vérification

```powershell
python -m unittest discover -s tests -v
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
- [`docs/ADR-009-APPLICATION-PILOTE-SUIVI-TACHES.md`](docs/ADR-009-APPLICATION-PILOTE-SUIVI-TACHES.md)
- [`docs/ADR-010-COURTAGE-CONNEXION-APPLICATIVE.md`](docs/ADR-010-COURTAGE-CONNEXION-APPLICATIVE.md)
- [`docs/ADR-011-CONSULTATION-CENTRALE-ACCES.md`](docs/ADR-011-CONSULTATION-CENTRALE-ACCES.md)
- [`docs/ADR-012-RETRAIT-DONNEES-SYNTHETIQUES.md`](docs/ADR-012-RETRAIT-DONNEES-SYNTHETIQUES.md)
- [`docs/ADR-013-REVOCATION-CENTRALE-ACCES.md`](docs/ADR-013-REVOCATION-CENTRALE-ACCES.md)
- [`docs/ADR-014-PUBLICATION-CATALOGUES-APPLICATIFS.md`](docs/ADR-014-PUBLICATION-CATALOGUES-APPLICATIFS.md)
- [`docs/ETAT-PREPROD-INFOMANIAK.md`](docs/ETAT-PREPROD-INFOMANIAK.md)
- [`docs/CONFORMITE-NSES.md`](docs/CONFORMITE-NSES.md)
- [`docs/CONTRAT-API-INTERNE.md`](docs/CONTRAT-API-INTERNE.md)
