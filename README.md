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
créer aucun droit applicatif. Il ne gère encore
ni mots de passe, ni jetons, ni interface réseau.

La première frontière d’API interne permet déjà d’évaluer un accès sans partager
la base avec les applications. Un transport HTTP fermé par défaut est validé en
local : sans adaptateur d’authentification, toute décision est refusée. La
validation OIDC et le déploiement sur la préproduction restent à brancher.

Les objets de gouvernance sont conservés dans la même frontière transactionnelle
que leur événement d’audit : une mutation sans preuve valide est annulée.

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

La commande de construction du paquet sera ajoutée lorsque le premier service
exécutable sera introduit. Aucun artefact de production n’est livré à ce stade.

## Documents

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/CONTRAT-IDENTITE-ACCES.md`](docs/CONTRAT-IDENTITE-ACCES.md)
- [`docs/PLAN-MIGRATION-SUIVI-TACHES.md`](docs/PLAN-MIGRATION-SUIVI-TACHES.md)
- [`docs/ADR-001-SEPARATION-RESPONSABILITES.md`](docs/ADR-001-SEPARATION-RESPONSABILITES.md)
- [`docs/ADR-002-STOCKAGE-ET-AUDIT.md`](docs/ADR-002-STOCKAGE-ET-AUDIT.md)
- [`docs/ADR-004-PORTAGE-SERVICE-NODE.md`](docs/ADR-004-PORTAGE-SERVICE-NODE.md)
- [`docs/ADR-005-MARIADB-PRODUCTION.md`](docs/ADR-005-MARIADB-PRODUCTION.md)
- [`docs/ADR-006-TRANSPORT-HTTP.md`](docs/ADR-006-TRANSPORT-HTTP.md)
- [`docs/ETAT-PREPROD-INFOMANIAK.md`](docs/ETAT-PREPROD-INFOMANIAK.md)
- [`docs/CONFORMITE-NSES.md`](docs/CONFORMITE-NSES.md)
- [`docs/CONTRAT-API-INTERNE.md`](docs/CONTRAT-API-INTERNE.md)
