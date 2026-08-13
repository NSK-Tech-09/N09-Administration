# Lot 49 — Déploiement progressif des sessions opposables en préproduction

Statut : **paliers `issue` et `enforce` déployés et recettés en préproduction**

Date de préparation : **13 août 2026**

## Objet

Ce lot orchestre le déploiement conjoint des lots 47 et 48 sans modifier la
production. Il fait de N09 – Suivi des tâches la première application pilote
dont une session peut être révoquée centralement, puis rend la propre session
de N09 – Administration opposable.

La progression reste volontairement découpée en paliers indépendants. Chaque
palier possède ses preuves, ses critères d'arrêt et son retour arrière avant
que le suivant ne soit ouvert.

## Références canoniques

| Composant | Commit à déployer | Release prévue | Commit actif constaté | Release active constatée |
|---|---|---|---|---|
| N09 – Administration | `2904e4c23362648aa14529d9209c6b2c795d6262` | `releases/2904e4c` | `958f3566595525ab89ca9e38897d62e0d81a76d9` | `releases/958f356` |
| N09 – Suivi des tâches | `0d1915de91fc15f9a966b1ccc79ef5655f821b02` | `releases/0d1915d` | `c0edcddd894518e691bb1c9904471fb9bbaa3f4f` | `releases/c0edcdd` |

Les deux commits cibles sont les commits de fusion de `main`. Une release
construite depuis une branche locale ou une autre empreinte est refusée.

## État initial vérifié en lecture seule

Constat public et Manager Infomaniak du 13 août 2026 :

- `https://preprod-admin.nsktech.fr/health` répond `200` ;
- le parcours authentifié `/admin/access` reste opérationnel ;
- la commande Administration cible explicitement `releases/958f356` ;
- `N09_ENVIRONMENT=preprod` ;
- `N09_SESSION_SHADOW_MODE=observe` ;
- aucune variable canonique `N09_ADMIN_SESSION_MODE` n'est encore définie ;
- aucune variable `N09_TASKS_SESSION_MODE` n'est encore définie ;
- `N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY=false` ;
- `https://preprod-taches.nsktech.fr/api/health` répond `200` ;
- la santé Tâches annonce le commit `c0edcddd894518e691bb1c9904471fb9bbaa3f4f` ;
- la base Tâches est prête au schéma `013_notification_event_quarantine` ;
- la commande Tâches cible explicitement `releases/c0edcdd` ;
- `N09_ENVIRONMENT=preproduction` côté Tâches ;
- le rejeu des révocations centrales n'est pas activé ;
- le planificateur de tâches du Manager est indisponible pour cet hébergement.

Le registre `application_sessions` d'Administration est déjà installé et a été
recetté en mode `observe` au lot 46. Aucune nouvelle migration Administration
n'est requise par les lots 47 et 48.

La migration Tâches `014_central_session_revocation_queue.sql` n'est pas encore
appliquée. Elle est additive. Sa procédure inverse refuse délibérément de
supprimer la file afin de préserver toute révocation encore en attente.

## Invariants non négociables

- cibles exactes : `preprod-admin.nsktech.fr` et
  `preprod-taches.nsktech.fr` ;
- bases exactes : `6p7h3x_n09_admin_preprod` et
  `6p7h3x_n09_tasks_preprod` ;
- aucune mutation de production ;
- deux sauvegardes logiques vérifiées avant toute migration ou bascule ;
- identité DDL durable et bornée à la seule base Tâches pour la migration 014 ;
- comptes d'exécution sans droit DDL ;
- releases précédentes et commandes de lancement conservées ;
- canaux externes de notification fermés ;
- aucun secret, cookie, identifiant de session ou empreinte de secret dans les
  preuves, commandes enregistrées ou journaux ;
- aucune suppression de la table `application_sessions` ni de la file
  `central_session_revocation_queue` pendant un retour arrière ;
- une seule modification de mode à la fois, suivie d'une recette complète.

## Phase 0 — Point de retour vérifié

Avant toute écriture distante :

1. enregistrer la date UTC et les deux réponses de santé ;
2. enregistrer les commandes de lancement actives sans recopier de secret ;
3. confirmer la présence et l'intégrité des releases `958f356` et `c0edcdd` ;
4. confirmer `N09_SESSION_SHADOW_MODE=observe` et l'absence des nouvelles
   variables canoniques ;
5. confirmer que la file `central_session_revocation_queue` est absente et que
   le schéma Tâches actif est `013_notification_event_quarantine` ;
6. vérifier la chaîne d'audit Administration ;
7. confirmer que les canaux externes sont fermés ;
8. produire et vérifier un export logique de chaque base.

Les sauvegardes attendues sont conservées dans les emplacements déjà dédiés :

```text
/srv/customer/backups/preprod-admin/lot49-pre-session-enforcement-<UTC>.sql.gz
/srv/customer/backups/preprod-taches/lot49-pre-session-enforcement-<UTC>.sql.gz
```

Pour chacune : taille non nulle, test gzip réussi, fin d'export présente et
empreinte SHA-256 consignée. Une sauvegarde non vérifiée interdit la suite.

## Phase 1 — Migration additive de Tâches

Appliquer avec l'identité DDL bornée à `6p7h3x_n09_tasks_preprod` :

```text
server-node/migrations/014_central_session_revocation_queue.sql
```

Contrôles obligatoires :

- version `014_central_session_revocation_queue` présente une seule fois dans
  `schema_migrations` ;
- table InnoDB présente ;
- sept colonnes, une clé primaire et un index d'échéance ;
- aucun champ de secret, cookie ou empreinte ;
- zéro ligne avant la première recette ;
- compte d'exécution capable de lire et d'écrire dans une transaction annulée ;
- compte d'exécution toujours incapable de créer ou supprimer une table ;
- santé Tâches encore servie par l'ancienne release après la migration.

La migration ne sera pas annulée par `DROP TABLE`. Un retour applicatif vers
`c0edcdd` ignore la table et la conserve comme preuve.

## Phase 2 — Construction des releases immuables

### Administration

- construire uniquement depuis
  `2904e4c23362648aa14529d9209c6b2c795d6262` ;
- installer les dépendances depuis le lockfile vérifié ;
- exécuter les suites Node.js et Python applicables ;
- vérifier l'intégrité de la release ;
- créer de nouveaux marqueurs propres au lot 49, sans réutiliser comme preuve
  les marqueurs d'une release antérieure.

### Suivi des tâches

- construire uniquement depuis
  `0d1915de91fc15f9a966b1ccc79ef5655f821b02` ;
- construire l'interface en mode cœur Node.js ;
- installer les dépendances depuis les lockfiles vérifiés ;
- exécuter les suites Node.js et les contrôles du frontal ;
- vérifier l'intégrité de la release et l'identité du paquet ;
- créer de nouveaux marqueurs propres au lot 49.

Les deux dossiers deviennent en lecture seule après validation. Les anciennes
releases restent intactes.

## Phase 3 — Déploiement préparatoire en mode `issue`

### Administration

Remplacer l'alias historique par les variables canoniques, sans changer le
comportement de sa propre session :

```text
N09_ADMIN_SESSION_MODE=observe
N09_ADMIN_SESSION_IDLE_TTL_MS=1800000
N09_ADMIN_SESSION_ABSOLUTE_TTL_MS=28800000
N09_ADMIN_SESSION_TOUCH_INTERVAL_MS=300000
N09_TASKS_SESSION_MODE=issue
```

Conserver :

```text
N09_ENVIRONMENT=preprod
N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY=false
```

La variable transitoire `N09_SESSION_SHADOW_MODE` peut être retirée seulement
après lecture de contrôle de la configuration canonique. Une copie datée du
fichier d'environnement précède l'édition.

Basculer la commande sur `releases/2904e4c` uniquement après présence de tous
les nouveaux marqueurs, puis redémarrer une seule fois et contrôler `/health`.

### Suivi des tâches

Conserver `N09_ENVIRONMENT=preproduction` et ajouter :

```text
N09_ALLOW_CENTRAL_SESSION_REVOCATION_REPLAY=true
N09_CENTRAL_SESSION_REVOCATION_BATCH_SIZE=25
```

Le planificateur Infomaniak étant indisponible, le rejeu est exécuté par un
worker enfant supervisé par la même commande que l'application, sur le modèle
déjà éprouvé du consommateur de notifications Administration. Le worker lance
`central-session-revocation-replay-cli.mjs` à intervalle borné, ne journalise
que les compteurs `selected`, `confirmed` et `pending`, et est arrêté avec le
processus principal.

La nouvelle commande doit :

- exiger les marqueurs de tests, sauvegardes, migration 014, intégrité et
  aptitude au déploiement ;
- pointer le frontal et le serveur vers `releases/0d1915d` ;
- exposer dans `/api/health` le commit complet cible et la date de construction ;
- démarrer le worker de rejeu et le serveur Node ;
- propager correctement l'arrêt aux deux processus.

Après bascule :

- `/api/health` doit annoncer le commit cible exact ;
- le schéma doit annoncer `014_central_session_revocation_queue` ;
- le registre, les tâches, les pièces jointes et les notifications doivent
  rester lisibles ;
- aucune session Tâches existante sans preuve ne doit être utilisée pour la
  recette du nouveau contrat.

## Phase 4 — Recette réelle du mode `issue`

1. fermer proprement l'ancienne session Tâches ;
2. ouvrir une nouvelle connexion via Administration ;
3. vérifier la création d'une unique session centrale liée à
   `n09-suivi-taches` ;
4. vérifier l'audit `application_session.created` sans référence complète,
   secret ni empreinte ;
5. vérifier l'accès nominal aux tâches selon les droits et le site existants ;
6. vérifier que la propre session Administration reste en `observe` ;
7. vérifier la chaîne d'audit ;
8. vérifier que la file locale est vide ;
9. vérifier que production et Énergie sont inchangées.

Cette phase ne révoque encore aucune session réelle.

## Phase 5 — Opposabilité de Suivi des tâches

Passer uniquement Administration de :

```text
N09_TASKS_SESSION_MODE=issue
```

à :

```text
N09_TASKS_SESSION_MODE=enforce
```

Après copie datée de l'environnement et redémarrage d'Administration :

1. prouver l'accès nominal avec la nouvelle session ;
2. prouver qu'une preuve absente ou altérée produit une nouvelle
   authentification et n'ouvre aucun droit ;
3. prouver qu'une indisponibilité centrale produit `503`, sans ouverture
   dégradée ;
4. révoquer une session de recette explicitement identifiée ;
5. prouver son refus immédiat côté Tâches ;
6. ouvrir une nouvelle session saine ;
7. tester la déconnexion nominale et confirmer la disparition de la ligne de
   file après confirmation centrale ;
8. tester une indisponibilité bornée : cookie effacé, ligne persistée, refus
   local immédiat, puis suppression uniquement après rejeu confirmé ;
9. vérifier les audits et la chaîne d'audit sans donnée sensible.

Toute panne centrale en mode `enforce` doit fermer l'accès ; aucun basculement
implicite vers `issue` n'est autorisé.

## Phase 6 — Opposabilité d'Administration

Cette phase ne s'ouvre qu'après validation complète du pilote Tâches.

Passer uniquement :

```text
N09_ADMIN_SESSION_MODE=observe
```

à :

```text
N09_ADMIN_SESSION_MODE=enforce
```

Puis :

1. contrôler `/health` ;
2. fermer la session Administration d'observation ;
3. ouvrir une nouvelle session Administration ;
4. prouver l'accès nominal ;
5. prouver le refus d'une preuve absente, altérée, révoquée ou expirée ;
6. prouver qu'une création centrale indisponible renvoie `503` sans cookie
   autonome ;
7. prouver qu'une déconnexion centrale indisponible renvoie `503` et conserve
   le cookie pour permettre un nouvel essai ;
8. prouver une déconnexion confirmée avant effacement du cookie ;
9. contrôler chaîne d'audit, droits, notifications et santé de Tâches.

La suppression de la compatibilité `shadowSession` et la rotation générale des
cookies restent hors de ce lot. Elles relèvent de l'étape 5 de `ADR-020` après
une période d'observation suffisante.

## Retour arrière

### Palier Tâches

1. remettre `N09_TASKS_SESSION_MODE=issue` ;
2. si nécessaire, remettre `N09_TASKS_SESSION_MODE=disabled` ;
3. restaurer la commande `releases/c0edcdd` ;
4. redémarrer et vérifier `/api/health` ;
5. conserver la migration 014 et toute ligne en attente ;
6. maintenir ou exécuter le rejeu jusqu'à confirmation des révocations déjà
   demandées.

### Palier Administration

1. remettre `N09_ADMIN_SESSION_MODE=observe` ;
2. si nécessaire, restaurer la commande `releases/958f356` et la copie
   d'environnement précédente ;
3. redémarrer et vérifier `/health` ;
4. conserver `application_sessions` et tous les audits.

Une restauration de base n'est envisagée qu'en cas de corruption indépendante,
après décision humaine explicite. Elle n'est jamais utilisée comme simple
retour de version.

## Critères d'arrêt immédiat

- commit ou release différents des références canoniques ;
- sauvegarde non vérifiable ;
- cible de base ambiguë ;
- migration 014 partielle ou schéma inattendu ;
- compte d'exécution doté d'un droit DDL ;
- test ou contrôle d'intégrité en échec ;
- santé non `200` ;
- commit ou schéma annoncés par la santé différents de la cible ;
- canal externe ouvert ;
- apparition d'un secret, cookie, identifiant de session complet ou empreinte
  sensible dans les journaux ou preuves ;
- chaîne d'audit invalide ;
- ancienne release ou commande de retour arrière indisponible ;
- file de révocation supprimée ou dette de révocation abandonnée.

## Preuves à consigner après exécution

| Preuve | Administration | Suivi des tâches |
|---|---|---|
| Commit et release | `2904e4c23362648aa14529d9209c6b2c795d6262`, `releases/2904e4c` | `0d1915de91fc15f9a966b1ccc79ef5655f821b02`, `releases/0d1915d` |
| Empreinte du paquet | manifeste interne vérifié | archive de transfert SHA-256 `9b12f48b82bfb05e4844f6d27f3069e4ae81c6d4ae7c3fbc59dd60f0a50add6f`, puis supprimée |
| Sauvegarde vérifiée | `20a3fcc88d226612a720bcc467dd93e7fc4214bd13679d16cf6000c711de99891a` | `9ef7fb3a3bbacbd929bb47f65c950cbbdaf9ed87e54cc4a3e71ca784a0cde0018` |
| Tests sur Infomaniak | 194 Node.js + 63 Python | 211 Node.js + build frontal `node-core` |
| Schéma | registre existant contrôlé | migration `014_central_session_revocation_queue`, 7 colonnes, 2 index et contrainte de cohérence |
| Mode préparatoire | `observe` | `issue` central |
| Mode opposable | `enforce` | `enforce` central |
| Santé publique | `/health` : `200`, `status=ok` | `/api/health` : `200`, commit cible, schéma 014, écriture centralement gardée |
| Session réelle | émission, accès, déconnexion centrale, puis réémission validés | émission, accès, révocation nominale et différée, puis réémission validés |
| Audit et chaîne | chaîne valide ; 8 créations, 2 expirations et 4 révocations constatées | événements portés par Administration |
| File de révocation | sans objet | passage contrôlé de 0 à 1 pendant la panne, puis retour automatique à 0 après rejeu confirmé |
| Retour arrière à blanc | release `958f356` et environnement daté conservés | release `c0edcdd` et environnement daté conservés |
| Production inchangée | aucune mutation de production | aucune mutation de production |

## Avancement réel du 13 août 2026

Le palier préparatoire `issue`, puis les deux paliers opposables `enforce`, sont
déployés et recettés. Leur ouverture a été explicitement autorisée après
lecture des preuves du palier préparatoire et exécutée séquentiellement, avec
retour arrière prêt avant chaque redémarrage.

- point de retour Administration contrôlé : `releases/958f356`, sept marqueurs
  présents, santé `200`, environnement `preprod`, mode historique `observe`,
  canaux externes fermés et fichier d'environnement en permissions `600` ;
- point de retour Tâches contrôlé : `releases/c0edcdd`, santé `200`, commit
  `c0edcddd894518e691bb1c9904471fb9bbaa3f4f`, schéma
  `013_notification_event_quarantine` et fichier d'environnement en
  permissions `600` ;
- sauvegarde Administration vérifiée :
  `/srv/customer/backups/preprod-admin/lot49-pre-session-enforcement-20260813T092939Z.sql.gz`,
  **19 251 octets**, gzip valide, fin d'export présente, SHA-256
  `20a3fcc88d226612a720bcc467dd93e7fc4214bd13679d16cf6000c711de99891a` ;
- sauvegarde Tâches vérifiée :
  `/srv/customer/backups/preprod-taches/lot49-pre-session-enforcement-20260813T092957Z.sql.gz`,
  **112 629 octets**, gzip valide, fin d'export présente, SHA-256
  `9ef7fb3a3bbacbd929bb47f65c950cbbdaf9ed87e54cc4a3e71ca784a0cde0018` ;
- release Administration `releases/2904e4c` construite depuis le commit exact,
  **194 tests Node.js** et **63 tests Python** réussis sur Infomaniak, marqueurs
  et manifeste d'intégrité présents, dossier figé en lecture seule ;
- le premier passage des tests Administration sous le fuseau UTC natif du
  terminal a correctement révélé un écart de conversion de dates. La suite a
  été rejouée avec `TZ=Europe/Paris`, fuseau de la commande applicative active,
  puis a réussi intégralement ; aucune modification du code n'a été nécessaire ;
- archive locale Tâches construite depuis le commit exact
  `0d1915de91fc15f9a966b1ccc79ef5655f821b02` : **7 129 591 octets**, SHA-256
  `9b12f48b82bfb05e4844f6d27f3069e4ae81c6d4ae7c3fbc59dd60f0a50add6f` ;
- le téléchargement anonyme de cette archive depuis Infomaniak reçoit `404`,
  comportement attendu pour le dépôt GitHub privé. Aucun secret GitHub n'a été
  placé dans le terminal ;
- compte SFTP ponctuel créé uniquement pour le transfert, archive vérifiée sur
  le serveur, sources extraites (**430 fichiers**, **8,7 Mo**), puis compte,
  archive distante, archive locale et dépendances temporaires supprimés ;
- migration 014 appliquée avec séparation des pouvoirs : le compte DDL a créé
  la table mais n'a pas pu écrire dans `schema_migrations`; le compte applicatif
  a inscrit la version sans recevoir de droit DDL ;
- structure contrôlée : **7 colonnes**, clés `PRIMARY` et
  `ix_central_session_revocation_due`, contrainte
  `ck_central_session_revocation_attempts` présente ; insertion de recette
  visible dans une transaction puis absente après `ROLLBACK` ;
- release Tâches construite sur Infomaniak : **211 tests Node.js réussis**,
  installation `pnpm 11.9.0` verrouillée, frontal `node-core` compilé,
  manifeste vérifié et dossier figé en lecture seule ;
- copies d'environnement conservées : Administration
  `.env.pre-lot49-20260813T100437Z`, Tâches
  `.env.pre-lot49-20260813T100204Z` ;
- Administration redémarrée sur `releases/2904e4c` avec les modes confirmés
  dans le journal de démarrage : `administration_session_mode=observe` et
  `tasks_session_mode=issue` ;
- Tâches redémarré sur `releases/0d1915d` ; santé publique `200`, commit complet
  cible, schéma `014_central_session_revocation_queue`, écriture
  `centrally_gated` et étape MariaDB connectée ;
- worker de rejeu supervisé actif : plusieurs cycles
  `central_session_revocation_replay` ont annoncé `selected=0`, `confirmed=0`
  et `pending=0` ;
- recette réelle : nouvelle authentification Infomaniak, session centrale
  `n09-suivi-taches` créée, accès aux **165 tâches**, détail d'une tâche et
  pièce jointe lisibles ;
- déconnexion Tâches recettée : session centrale immédiatement révoquée,
  retour à l'écran de connexion et **zéro** ligne dans la file locale ;
- nouvelle connexion effectuée après la révocation : une session Tâches active
  a été réémise et laissée utilisable ; Administration conserve une session
  active en mode `observe` à ce stade ;
- chaîne d'audit recalculée après la recette : `audit_chain_valid=true` ; le
  registre contient alors quatre événements `application_session.created`, un
  événement `application_session.expired` et un événement
  `application_session.revoked`, sans donnée sensible consignée dans la preuve ;
- anciennes releases, sauvegardes et commandes de retour arrière conservées ;
  aucun secret, cookie ou identifiant complet de session n'a été consigné.

### Ouverture des paliers opposables

- copie Administration créée avant le premier verrou :
  `.env.pre-lot49-tasks-enforce-20260813T104246Z` ; seule la valeur
  `N09_TASKS_SESSION_MODE` est passée de `issue` à `enforce` ;
- redémarrage contrôlé : le journal a confirmé
  `administration_session_mode=observe` et `tasks_session_mode=enforce` ;
- recette Tâches nominale : session centrale reconnue, identité rattachée,
  droits recalculés et **165 tâches** accessibles ;
- appels sans cookie puis avec un cookie volontairement altéré : refus `401`
  dans les deux cas ;
- déconnexion nominale : retour à l'écran de connexion, révocation centrale
  immédiate, puis nouvelle session saine ;
- panne centrale bornée réalisée en arrêtant uniquement le processus
  Administration de préproduction : actualisation refusée avec le message
  `Identité centrale indisponible` et détail protégé non livré ;
- déconnexion Tâches pendant cette panne : cookie local effacé, retour à la
  connexion et file durable passée à `QUEUE_PENDING=1` ;
- après remise en service d'Administration et santé `200`, le worker périodique
  a confirmé la révocation et ramené la file à `QUEUE_PENDING=0`, sans action
  manuelle ni suppression de preuve ; une nouvelle session Tâches saine a
  ensuite été émise ;
- copie Administration créée avant le second verrou :
  `.env.pre-lot49-admin-enforce-20260813T104929Z` ; seule la valeur
  `N09_ADMIN_SESSION_MODE` est passée de `observe` à `enforce` ;
- second redémarrage contrôlé : le journal a confirmé simultanément
  `administration_session_mode=enforce` et `tasks_session_mode=enforce` ;
- santé Administration `200` ; accès sans preuve et avec preuve altérée refusés
  en `401` ;
- authentification Infomaniak réelle, identité NSK rattachée, page centrale des
  utilisateurs et accès lisible avec **1 identité active**, **2 applications
  actives** et **6 affectations actives** ;
- déconnexion Administration confirmée avant effacement du cookie, retour à
  l'accueil non authentifié, puis nouvelle session réelle émise et laissée
  active ;
- les variantes de panne du registre propre à Administration — création en
  `503` sans cookie autonome, déconnexion en `503` avec conservation du cookie
  — restent couvertes par les tests exécutés dans la release immuable. Aucune
  coupure volontaire de la base partagée n'a été provoquée pour les rejouer en
  réel, afin de ne pas élargir le périmètre de risque ;
- contrôle final du registre : `n09-administration` total `4`, actif `1` ;
  `n09-suivi-taches` total `4`, actif `1` ;
- contrôle final de l'audit : `application_session.created=8`,
  `application_session.expired=2`, `application_session.revoked=4` et
  `audit_chain_valid=true` ;
- santés finales : Administration `status=ok` ; Tâches `status=ok`, commit
  `0d1915de91fc15f9a966b1ccc79ef5655f821b02`, schéma
  `014_central_session_revocation_queue` et écriture `centrally_gated` ;
- production, Énergie, releases antérieures, sauvegardes et notifications
  externes sont restées inchangées.

## Références

- `ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`
- `LOT-46-ACTIVATION-OBSERVATION-SESSIONS-PREPROD.md`
- `LOT-47-OPPOSABILITE-SESSIONS-SUIVI-TACHES.md`
- `LOT-48-OPPOSABILITE-SESSIONS-ADMINISTRATION.md`
- N09 – Suivi des tâches : `LOT-40-SESSIONS-CENTRALES-OPPOSABLES.md`
- `ARC-008`, `ARC-010`, `ARC-012`, `ARC-013`, `ARC-016`
- `ERG-016`, `ERG-032`, `TST-001`
