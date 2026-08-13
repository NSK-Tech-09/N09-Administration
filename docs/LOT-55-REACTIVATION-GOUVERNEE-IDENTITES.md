# Lot 55 — réactivation gouvernée des identités

Statut : **déployé et recetté en préproduction**

Date : **13 août 2026**

## Objet

Compléter le cycle de vie ouvert par le lot 54 sans réintroduire les risques que
la suspension atomique a supprimés. Une identité `suspended` peut revenir à
l’état `active` uniquement après une nouvelle décision humaine explicite et
auditée. Cette transition ne restaure jamais une ancienne session.

La réactivation n’accorde aucun droit nouveau : les affectations conservées sont
à nouveau évaluées par les règles centrales au prochain parcours
d’authentification. Une nouvelle connexion reste donc obligatoire.

## Séparation des responsabilités

Le catalogue Administration passe en version 6 et ajoute exactement :

- la permission `administration:identities:reactivate` ;
- le rôle global `identity-reactivation-administrator` ;
- l’action de réactivation dans la console existante `/admin/identities`.

Le pouvoir de réactivation est distinct du pouvoir de suspension
`administration:identities:suspend`. Posséder l’un ne confère jamais l’autre.
Leur attribution reste explicite, auditée et bornée à la préproduction. La
réactivation possède son propre amorçage et son propre verrou d’activation ;
relancer l’amorçage historique de la suspension ne peut donc pas élargir
silencieusement les pouvoirs d’une personne.

## Invariants de sécurité

Après contrôle de la permission exacte, de l’état attendu `suspended`, de la
cible scellée, du jeton CSRF et d’une justification de 20 à 500 caractères, le
service :

1. verrouille l’identité cible ;
2. vérifie qu’elle est toujours suspendue ;
3. verrouille et contrôle l’absence de toute session encore active ;
4. passe l’identité à `active` ;
5. inscrit l’événement `identity.reactivated` dans la chaîne d’audit ;
6. valide l’ensemble dans une transaction unique.

Si une session active subsiste ou apparaît concurremment, toute l’opération est
annulée. Les sessions révoquées restent révoquées. Les sessions expirées ne sont
ni modifiées ni prolongées. L’événement d’audit inscrit explicitement
`restored_sessions: 0`.

## Interface et minimisation

La console présente l’action seulement pour une identité suspendue et seulement
à une personne disposant du pouvoir de réactivation. Elle n’expose aucun cookie,
secret, identifiant technique de session ou empreinte. La cible réelle voyage
dans un jeton chiffré, authentifié, lié à l’opérateur et de courte durée.

## Validation locale

La validation complète réussit :

- **242 tests Node.js** ;
- **63 tests Python** ;
- séparation stricte des pouvoirs de suspension et de réactivation ;
- transition MariaDB et audit dans une transaction unique ;
- rollback complet lorsqu’une session active subsiste ;
- conservation inchangée des sessions révoquées et expirées ;
- refus des cibles ou états périmés, des jetons altérés et des demandes sans
  permission exacte ;
- chaîne d’audit valide et absence de restauration de session.

## Activation en préproduction

Le **13 août 2026**, le commit canonique
`5d64bc17e5b27cf31b242450b7b8b5850b8de9c0` a été activé dans la release
immuable `releases/5d64bc1`. L’archive complète porte l’empreinte SHA-256
`258db8933ca3b79091d6f17fefda04524a28c5c369cf78adce5d2904ef451c7c` ;
**192 fichiers source**, **242 tests Node.js** et **63 tests Python** ont été
validés sur Infomaniak avant le gel en lecture seule.

La sauvegarde préalable
`/srv/customer/backups/preprod-admin/lot55-pre-identity-reactivation-20260813T213558Z.sql.gz`
pèse **32 921 octets**, est valide au format gzip et porte l’empreinte
`47237d701af58da710c82f95b13d626f36b51b53194372442b22a18e727884`.
Le catalogue Administration v6 est publié avec l’empreinte
`23be37690476002a7b79e58a8fb17e7127a39ce30b530804cfdc99fe5bed3a33`.
L’amorçage séparé a attribué le seul rôle
`identity-reactivation-administrator` à l’identité principale ; sa seconde
exécution est restée strictement idempotente.

Le changement de commande de démarrage a été accepté par Infomaniak, mais la
recette a détecté que le processus en mémoire servait encore le lot 54. Aucun
état métier n’a alors été modifié. Après un redémarrage explicite et contrôlé,
la console a présenté les pouvoirs distincts de suspension et de réactivation
du lot 55.

La recette réelle a réactivé **Fred TRAVERS — Recette** depuis l’interface avec
une justification explicite. Le contrôle direct de MariaDB confirme :

- identité `active` ;
- **0 session active** ;
- **0 ancienne session restaurée** ;
- la session historiquement révoquée reste révoquée ;
- dernier événement `identity.reactivated` conforme ;
- chaîne d’audit valide.

`/health` répond `200`, l’administration anonyme répond `401` et un cycle réel
du worker de notifications se termine avec succès, sans élément réclamé,
réessayé ni placé en quarantaine. Les émissions externes restent désactivées.
La preuve scellée est conservée dans
`/srv/customer/backups/preprod-admin/lot55-recipe-20260813T2200Z.txt`, en mode
`600`, avec l’empreinte
`4928140aa32c7d29f208bdb791c4640050e8927b004b98bd0ad2de4962395a19`.

La release précédente `releases/551db4b` et la sauvegarde préalable restent
disponibles pour retour arrière. La production et N09 – Énergie n’ont pas été
modifiées.
