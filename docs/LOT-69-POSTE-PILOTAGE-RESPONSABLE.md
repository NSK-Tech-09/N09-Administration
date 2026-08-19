# Lot 69 — Poste de pilotage du responsable NSK Tech 09

## Décision

Le responsable légal et opérationnel dispose d’une autorité complète sans rôle
universel ni permission générique. Cette autorité reste composée de huit pouvoirs
indépendants : rattachements, registre, décisions d’accès, notifications,
sessions, suspension, réactivation et désactivation.

L’accueil Administration présente leur état réel sous forme d’un poste de
pilotage. Un pouvoir absent reste visible comme manquant ; une panne du registre
n’est jamais présentée comme une autorisation.

## Habilitation de production

Le workflow manuel `grant-legal-owner-authority.yml` est la seule procédure
prévue pour compléter cette autorité en production. Il exige simultanément :

- la confirmation littérale `GRANT_NSK_LEGAL_OWNER_AUTHORITY` ;
- une justification de 30 à 500 caractères ;
- l’environnement GitHub protégé `production` ;
- la release publique exactement égale au commit qui porte le workflow ;
- la base dont le nom se termine par `_prod` ;
- l’identité active `f.travers@nsktech.fr` ;
- le catalogue Administration version 7 et chacun de ses rôles actifs.

Chaque pouvoir manquant crée une affectation séparée et un événement d’audit.
La procédure est idempotente : un pouvoir déjà actif reste inchangé. Elle ne
permet ni auto-suspension, ni auto-désactivation, ni révocation depuis l’écran du
pouvoir central de décision.

## Vérifications

- affichage explicite d’une autorité incomplète puis complète `8/8` ;
- refus hors production, sur mauvaise base, mauvaise identité ou confirmation
  ambiguë ;
- contrôle du catalogue avant toute écriture ;
- idempotence et validité finale de la chaîne d’audit.
