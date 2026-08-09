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

Socle fondateur local. Le premier incrément contient le modèle de domaine et le
moteur déterministe de décision d’accès. Il ne gère encore ni mots de passe, ni
jetons, ni persistance, ni interface réseau.

## Vérification

```powershell
python -m unittest discover -s tests -v
```

## Documents

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/CONTRAT-IDENTITE-ACCES.md`](docs/CONTRAT-IDENTITE-ACCES.md)
- [`docs/PLAN-MIGRATION-SUIVI-TACHES.md`](docs/PLAN-MIGRATION-SUIVI-TACHES.md)
- [`docs/ADR-001-SEPARATION-RESPONSABILITES.md`](docs/ADR-001-SEPARATION-RESPONSABILITES.md)
- [`docs/CONFORMITE-NSES.md`](docs/CONFORMITE-NSES.md)
