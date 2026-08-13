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

Le registre de sessions entre maintenant dans sa phase d'observation locale.
Lorsqu'elle sera explicitement activée en préproduction, une nouvelle connexion
rattachée d'Administration pourra créer une session centrale et comparer son
état en arrière-plan. Le cookie actuel restera seul opposable : absence,
divergence, expiration, révocation ou panne du registre ne modifieront encore
aucun accès. Les mesures structurées excluent identités, références, secrets,
empreintes et cookies ; voir `docs/LOT-45-OBSERVATION-INOPPOSABLE-SESSIONS.md`.

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
- [`docs/ADR-015-OCTROIS-APPLICATIFS-GOUVERNES.md`](docs/ADR-015-OCTROIS-APPLICATIFS-GOUVERNES.md)
- [`docs/ADR-016-RECEPTION-CENTRALE-NOTIFICATIONS.md`](docs/ADR-016-RECEPTION-CENTRALE-NOTIFICATIONS.md)
- [`docs/ADR-017-MATERIALISATION-CENTRE-NOTIFICATIONS.md`](docs/ADR-017-MATERIALISATION-CENTRE-NOTIFICATIONS.md)
- [`docs/ADR-018-OBSERVABILITE-NOTIFICATIONS.md`](docs/ADR-018-OBSERVABILITE-NOTIFICATIONS.md)
- [`docs/ADR-019-TRAITEMENT-AUTONOME-NOTIFICATIONS.md`](docs/ADR-019-TRAITEMENT-AUTONOME-NOTIFICATIONS.md)
- [`docs/ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`](docs/ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md)
- [`docs/LOT-45-OBSERVATION-INOPPOSABLE-SESSIONS.md`](docs/LOT-45-OBSERVATION-INOPPOSABLE-SESSIONS.md)
- [`docs/LOT-46-ACTIVATION-OBSERVATION-SESSIONS-PREPROD.md`](docs/LOT-46-ACTIVATION-OBSERVATION-SESSIONS-PREPROD.md)
- [`docs/ETAT-PREPROD-INFOMANIAK.md`](docs/ETAT-PREPROD-INFOMANIAK.md)
- [`docs/CONFORMITE-NSES.md`](docs/CONFORMITE-NSES.md)
- [`docs/CONTRAT-API-INTERNE.md`](docs/CONTRAT-API-INTERNE.md)
