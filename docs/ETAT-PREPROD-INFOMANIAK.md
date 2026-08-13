

# État de la préproduction Infomaniak

Date du constat : **10 août 2026**  
Périmètre : **N09 – Administration**

## État confirmé

- MariaDB **10.11.18** sur `6p7h3x.myd.infomaniak.com:3306` ;
- base dédiée : `6p7h3x_n09_admin_preprod` ;
- compte d'exécution : `6p7h3x_n09arun` ;
- droits du compte d'exécution : **lecture et écriture uniquement** sur la base
  Administration, sans administration et sans accès à la base Suivi des tâches ;
- compte temporaire de migration supprimé après installation du schéma ;
- aucun secret versionné ou conservé dans un fichier de travail.

Le site `preprod-admin.nsktech.fr` est créé sur l'hébergement dédié **N09 -
Coeur et Administration** du Server Cloud. Il utilise Node.js **24**, écoute sur
le port interne `3000` et exécute le transport HTTP versionné de N09 –
Administration. Le domaine est propagé, le certificat est sécurisé et le site
est en ligne. Aucune application de l'écosystème n'y est encore raccordée.

Le secret MariaDB actif est stocké uniquement dans le fichier d'environnement
du site, hors dépôt, avec les permissions `600`. Un premier secret généré a été
affiché dans la console à la suite d'un chemin SSH incorrect ; il a été
immédiatement révoqué avant utilisation, l'historique de session a été effacé et
un nouveau secret non affiché a été installé.

Le schéma versionné `service-node/mariadb/schema.sql` a été appliqué avec succès.
Les cinq tables suivantes existent :

- `identities` ;
- `applications` ;
- `access_assignments` ;
- `audit_events` ;
- `audit_chain_head`.

Les déclencheurs `audit_events_no_update` et `audit_events_no_delete` sont
installés. La tête de chaîne initiale existe, sans événement métier.

## Sauvegarde et restauration vérifiées

Infomaniak expose une sauvegarde de la base datée du **10 août 2026 à
08:15:54**. Elle est sélectionnable et téléchargeable depuis le Manager.

Un export logique complet a aussi été restauré dans la base isolée temporaire
`6p7h3x_n09_admin_restore`. Le premier essai a confirmé que le compte
d'exécution ne peut pas exporter les déclencheurs, conformément à ses droits
minimaux. Un compte éphémère a donc reçu les seuls privilèges nécessaires pour
l'exercice.

L'export MariaDB contenait le `DEFINER` technique d'origine des déclencheurs. La
restauration isolée l'a refusé sans privilège global ; la clause a été retirée
de la copie avant un second essai réussi. La sauvegarde testée faisait **8 706
octets** et portait l'empreinte SHA-256
`8539254002facd335179e3020ad58027c592480cc2c8a3633a5df9ab87295143`.

La base restaurée contenait cinq tables, deux déclencheurs, une tête de chaîne
d'audit et aucune donnée utilisateur. Le code retour final était `0`. La base
isolée, le compte éphémère, son secret et le fichier SQL temporaire ont ensuite
été supprimés. Les deux bases et les deux comptes permanents sont les seuls
éléments restants.

Une tentative de connexion depuis l'environnement local a expiré. MariaDB n'est
donc pas considérée comme accessible depuis Internet. Le test du compte
d'exécution a été effectué depuis le site Node hébergé sur le même Server Cloud.
Il confirme :

- la connexion interne à MariaDB et la présence des cinq tables (`RC=0`) ;
- l'écriture autorisée dans une transaction puis son rollback effectif
  (`1` pendant la transaction, `0` après rollback) ;
- le refus d'une mise à jour et d'une suppression dans `audit_events` par les
  deux déclencheurs d'immutabilité (`SQLSTATE 45000`) ;
- l'absence finale de toute donnée de test (`0`).

## Transport et données synthétiques vérifiés

Les PR **#14** et **#15** ont été fusionnées avant déploiement. La version active
porte le commit `72de3040441edd0add88d4d0d74ae67c10b33de1`. Elle est installée
dans un dossier de version distinct ; la version précédente reste disponible
pour un retour arrière.

Les dépendances ont été installées avec pnpm **11.16.0** et le lockfile validé.
Les **45 tests Node** réussissent également sur l'environnement Infomaniak.

Le frontal managé exige une écoute sur l'interface du conteneur. Cette exception
est bornée par `N09_TRUSTED_REVERSE_PROXY=true`, sans ouverture d'un port
applicatif brut. Les contrôles réels confirment :

- `GET https://preprod-admin.nsktech.fr/health` : `200` et `{"status":"ok"}` ;
- absence de cache et protection `nosniff` sur la réponse ;
- `POST /internal/v1/access-decisions` sans OIDC : `401` et
  `authentication_required` ;
- secret MariaDB toujours hors dépôt et fichier d'environnement toujours en
  permissions `600`.

Le premier amorçage a créé exactement une identité, une application et une
affectation synthétiques. Deux exécutions suivantes n'ont rien recréé
(`created: []`). Chaque passage a confirmé une chaîne d'audit valide. L'adresse
utilisée appartient au domaine réservé `example.invalid` ; aucune donnée
utilisateur réelle n'a été introduite.

## Adaptateur OIDC déployé

Les PR **#18**, **#20** et **#21** ont été validées par GitHub Actions puis
fusionnées. Cette étape portait le commit
`a25efe4f7a13f56d54437dfdf0faf6182bd6a4bc`, isolé dans
`releases/a25efe4f`. Les versions `72de3040`, `91c67d0` et `7720a1da` sont
conservées pour le retour arrière.

L'application OAuth **N09 Administration – Préproduction** est enregistrée
chez Infomaniak avec l'unique retour
`https://preprod-admin.nsktech.fr/auth/infomaniak/callback`. Les secrets sont
hors dépôt et hors base métier dans le fichier d'environnement en permissions
`600`. Les secrets affichés pendant l'amorçage ont été renouvelés avant usage.
Le terminal managé ajoutait silencieusement ses marqueurs de collage au secret
masqué : la longueur enregistrée était de 76 caractères au lieu de 64 et
Infomaniak répondait `invalid_client`. Les marqueurs ont été retirés sans lire
la valeur. Un essai avec un code volontairement invalide a ensuite obtenu
`invalid_grant`, confirmant que le Client ID et le secret étaient reconnus.

Les **54 tests Node** réussissent aussi sur Infomaniak. Les constats publics
confirment :

- `GET /health` : `200` et `{"status":"ok"}` ;
- `GET /` : portail N09 et action « Continuer avec Infomaniak » ;
- `GET /auth/infomaniak/start` : redirection `302` vers l'autorisation
  Infomaniak, PKCE S256 et cookie temporaire `HttpOnly`, `Secure`,
  `SameSite=Lax` ;
- consentement réel Infomaniak, échange du code, signature RS256 et claims
  vérifiés de bout en bout ;
- session maintenue après redémarrage du service ;
- identité externe reconnue avec l'état strict `link_required` ;
- aucun compte, rattachement, rôle ou droit créé automatiquement.

Le diagnostic temporaire n'exposait qu'un code interne prédéfini, jamais un
secret, un jeton, le code OAuth ou une donnée personnelle. Il a été remis à
`false` puis le service a été redémarré. Le comportement nominal ne présente
donc plus aucun détail d'échec.

## Rattachement réel validé

La PR **#23** a été validée par GitHub Actions puis fusionnée. La version active
porte le commit `5ab7a261b46652a4abce3364bca843c7ba888581` et est isolée dans
`releases/5ab7a261`. La version `a25efe4f` reste disponible pour un retour
arrière.

La migration MariaDB a ajouté les tables `external_identities` et
`external_identity_link_requests`. Le compte applicatif a correctement refusé
la création de tables ; la migration a donc été appliquée avec la session
administrative prévue, puis les droits de lecture applicatifs ont été vérifiés.

Les **60 tests Node** réussissent sur Infomaniak. Le parcours réel confirme :

- création d'une demande temporaire après consentement et preuve OIDC valides ;
- persistance de la demande et de son événement d'audit dans la même
  transaction ;
- décision explicite du titulaire, avec identité NSK cible et justification ;
- création du lien externe sans rôle, affectation ou droit applicatif ;
- chaîne d'audit valide après la décision ;
- nouvelle authentification reconnue avec l'état `authenticated` et l'identité
  NSK rattachée ;
- zéro affectation pour l'application pilote tant qu'une autorisation séparée
  n'a pas été décidée.

## Administration authentifiée des rattachements validée

La PR **#25** a été validée par GitHub Actions puis fusionnée dans `main` avec
le commit `9ea0c8a2e4079e89f222e8d8a1bada619672bec2`. La release active est isolée
dans `releases/9ea0c8a2` ; la release `5ab7a261` reste disponible pour un retour
arrière. Le clone temporaire utilisé pendant le déploiement a été supprimé.

Les dépendances ont été installées avec le lockfile vérifié et les **72 tests
Node** réussissent sur Infomaniak. Le processus a été redémarré explicitement
après la bascule et le journal du Manager confirme son démarrage sur le port
interne `3000`. Les contrôles publics confirment toujours :

- `GET /health` : `200` et `{"status":"ok"}` ;
- absence de cache et protection `nosniff` ;
- site déclaré en ligne et sécurisé dans le Manager.

L'amorçage ponctuel de la gouvernance a créé exactement l'application centrale
`n09-administration` et une affectation pour l'identité NSK de **Fred TRAVERS**.
Cette affectation porte uniquement la permission
`administration:identity-links:decide`. L'opération était bornée à la base
`_preprod`, justifiée, idempotente et a confirmé la validité de la chaîne
d'audit.

Après renouvellement de la session OIDC, le parcours réel confirme :

- identité Infomaniak reconnue et rattachée à Fred TRAVERS ;
- présence de l'entrée « Administrer les rattachements » uniquement pour cette
  identité explicitement autorisée ;
- ouverture de l'écran des demandes avec protection CSRF ;
- aucune demande en attente au moment du constat ;
- aucun rôle ni droit applicatif créé par ce pouvoir administratif ou par un
  rattachement.

## Première application pilote raccordée

Les PR **#27** de N09 – Administration et **#7** de N09 – Suivi des tâches ont
été fusionnées le **10 août 2026**. La release Administration active porte le
commit `1ed7c308322c056d6441f06937594a31ce59e0fb` et la release précédente
`9ea0c8a2` reste disponible pour un retour arrière immédiat.

Les **78 tests Node** Administration et les **20 tests Node** Suivi des tâches
réussissent sur Infomaniak. Le client technique `tasks-preprod` possède un
secret aléatoire propre à la préproduction, stocké uniquement dans les deux
fichiers d'environnement en permissions `600`. Aucun cookie ou secret humain
n'est partagé entre les sous-domaines.

L'amorçage idempotent a créé l'application `n09-suivi-taches` et une seule
affectation pour l'identité NSK active de Fred TRAVERS. Cette affectation porte
uniquement `tasks:read`. La chaîne d'audit est valide et aucun pouvoir
d'administration, d'écriture ou de rattachement n'a été ajouté.

La preuve interservices réelle confirme :

- première décision signée : `200`, `access_granted` ;
- rejeu strictement identique : `401` ;
- `GET /health` : `200` après redémarrage explicite ;
- secret absent des journaux et des réponses.

## Révocation centrale auditée validée

La PR **#32** de N09 – Administration a été validée par GitHub Actions puis
fusionnée dans `main` le **10 août 2026** avec le commit
`e89d95ee0dada37bc3f8b4e368a470ae1c69aae5`. La release active est isolée dans
`releases/e89d95ee` et la release `98324ab4` reste intacte pour un retour
arrière immédiat.

Les dépendances ont été installées avec le lockfile vérifié et les **103 tests
Node** réussissent sur Infomaniak. La commande d'exécution cible la nouvelle
release, le processus a été redémarré explicitement sur le port interne `3000`
et `GET /health` répond `200` avec `{"status":"ok"}`.

L'amorçage idempotent, limité à la base `6p7h3x_n09_admin_preprod`, a créé une
seule affectation supplémentaire pour l'identité NSK active de Fred TRAVERS.
Elle porte uniquement `administration:access:decide`. La chaîne d'audit est
valide ; la corrélation de l'opération est
`8f0f4e94-59d7-42a1-92ff-5745a48b7a3b`.

Le parcours réel authentifié confirme :

- présence de l'entrée « Décider les révocations » uniquement pour Fred ;
- pouvoir `administration:access:decide` visible mais non révocable depuis
  l'écran général ;
- justification obligatoire pour les autres affectations actives ;
- une identité active, deux applications actives et quatre affectations
  actives après l'amorçage ;
- aucune révocation réelle et aucun octroi arbitraire pendant la validation.

## Catalogues applicatifs publiés et validés

La PR **#34** de N09 – Administration a été fusionnée avec le commit
`6acc1ac9299a5059dcf5445c2ca88efba3eec0e7`. La release active est isolée dans
`releases/6acc1ac9` ; `releases/e89d95ee` reste disponible pour un retour
arrière immédiat. Les **112 tests Node** réussissent sur Infomaniak et
`GET /health` répond `200` avec `{"status":"ok"}` après le redémarrage
explicite.

La PR **#10** de N09 – Suivi des tâches a été fusionnée avec le commit
`232470688c732be37fa148b2e3434a00c4485baf`. La release
`releases/23247068` a été reconstruite depuis la release active précédente,
avec vérification SHA-256 des huit fichiers modifiés. Les **31 tests Node**
réussissent sur Infomaniak et `GET /api/health` confirme ce commit exact, la
base prête et le mode lecture seule.

La table additive `application_access_catalog_versions` a été créée sur la
seule base `6p7h3x_n09_admin_preprod`. L'identité MariaDB de migration, limitée
à cette base, a été créée pour l'opération puis supprimée ; seuls les deux
utilisateurs applicatifs permanents subsistent.

Les catalogues version 1 ont été publiés et affichés dans le registre :

- N09 – Administration : empreinte
  `26e5ff8ec29ae1faeb3ce688e383a63b059047f21b4a3e26dad34f65773159ad` ;
- N09 – Suivi des tâches : empreinte
  `b550eda66d0cb82c1c0974854daa221231120da6f66d1430d71b7dd096c90961`.

Chaque répétition a renvoyé `created: false` avec la même empreinte. La chaîne
d'audit est valide après la publication interservices. Le parcours authentifié
affiche une identité active, deux applications actives et quatre affectations
actives, soit exactement l'état antérieur : aucun octroi, retrait ou profil
métier n'a été créé par ce lot. Les rôles futurs de Suivi des tâches restent
explicitement `planned` et la création automatique par courriel reste interdite.

## Octrois gouvernés et commandes de tâches déployés

La PR **#36** de N09 – Administration a été fusionnée dans `main` avec le commit
`112e18b2c71b7d968af4aee50a3420888ae0ebcf`. La release active est isolée dans
`releases/112e18b` et son démarrage est conditionné par la réussite des tests et
la publication du catalogue Administration version 2.

Les **117 tests Node.js** réussissent sur Infomaniak. Le catalogue version 2 a
été publié par la commande ponctuelle prévue à cet effet, puis le service a été
redémarré explicitement. Le contrôle public confirme :

- `GET https://preprod-admin.nsktech.fr/health` : `200` et
  `{"status":"ok"}` ;
- `GET /api/health` : `404`, conformément au contrat propre à Administration ;
- `GET /admin/access` sans session : écran « Connexion requise » ;
- aucun utilisateur, rattachement, octroi ou retrait créé pour la validation.

La PR **#31** de N09 – Suivi des tâches a été fusionnée avec le commit
`ba92ee1a2be208e6343d70d96ca5124b3653d322`. Son catalogue version 2 est publié
et la décision centrale peut désormais distinguer `tasks:read` de
`tasks:write`, avec périmètre de site et prérequis applicatifs explicites.

La recette authentifiée réelle du 11 août 2026 confirme en outre :

- identité Infomaniak vérifiée pour **Fred TRAVERS**, rattachée à l'identité NSK
  `60a40cd7-f2a4-4393-8021-9f806b42b41a` ;
- registre central accessible en lecture avec une identité active, deux
  applications actives et quatre affectations actives ;
- catalogues version 2 visibles pour Administration et Suivi des tâches ;
- rôles actifs `tasks-reader` et `tasks-writer` proposés uniquement comme
  octrois conditionnels sur un site exact ;
- pouvoir `administration:access:decide` protégé de sa propre révocation dans
  l'interface générale ;
- aucune demande de rattachement en attente ;
- aucun octroi, retrait, rattachement ou changement de donnée pendant la
  recette.

## Prochain jalon

Le prochain jalon est la preuve applicative du refus d'une commande de tâche
sans octroi `tasks:write`, au moyen d'un scénario explicitement réversible ou
sans mutation. Aucune tâche ni affectation réelle ne doit être créée uniquement
pour prouver le fonctionnement.

La production et les applications existantes restent inchangées.

## Lot 38 — réception centrale des notifications validée

Le **12 août 2026**, la PR **#38** a été fusionnée avec le commit
`c5835a49e440f05104026804ef1e819e1cbe1cd3`. La release immuable
`releases/c5835a4` a réussi ses **129 tests Node.js** sur Infomaniak. Ses
dépendances d'exécution ont été reprises de la release précédente après
vérification de l'identité SHA-256 de `package.json` et `pnpm-lock.yaml`, puis
un garde-fou dédié a été posé avant la bascule.

Avant migration, l'export logique
`lot38-pre-migration-20260812T141856Z.sql.gz` a été créé dans
`/srv/customer/backups/preprod-admin`. Il pèse **15 058 octets** et porte
l'empreinte SHA-256
`674ed1579edebb1377b979e7f6afc0df68a18f703eea37a37dcf1cbfb3746c90`.

La table durable `notification_events` et ses deux déclencheurs
`notification_events_no_delete` et `notification_events_payload_immutable`
sont installés. La commande d'exécution cible désormais `releases/c5835a4` et
vérifie les marqueurs de tests, de sauvegarde, de schéma, d'intégrité, de
catalogue et de dépendances avant tout démarrage. Les contrôles réels
confirment :

- `GET /health` : `200` et `{"status":"ok"}` ;
- `POST /internal/v1/notification-events` sans signature : `401` et
  `authentication_required`, ce qui prouve l'exposition du nouveau contrat
  sans affaiblir son authentification ;
- réception exacte des événements `task.archived` et `task.restored` issus de
  Suivi des tâches, chacun avec une empreinte SHA-256 de 64 caractères ;
- état initial central `pending`, zéro tentative de traitement et aucune
  erreur ;
- aucun canal externe activé et aucun message envoyé.

Le compte DDL partagé `6p7h3x_n09ddl` avait reçu temporairement les droits de
lecture et d'administration sur la base Administration. Ces deux droits ont
été retirés après validation. Il ne référence plus que
`6p7h3x_n09_tasks_preprod`, tandis que le compte d'exécution Administration
reste limité à sa propre base.

La release précédente `releases/112e18b` et la sauvegarde vérifiée restent
disponibles pour un retour arrière conservateur. La production est restée
inchangée.

## Prochain jalon après le lot 38

Concevoir puis valider le traitement interne des deux événements centraux et
les canaux réellement nécessaires, en maintenant les canaux externes fermés
jusqu'à une décision explicite. La promotion en production reste interdite
tant que la comparaison avec les comportements historiques n'est pas achevée.

## Lots 50 et 51 — sessions anciennes fermées et gestion personnelle déployée

Le **13 août 2026**, les lots 50 et 51 ont été déployés conjointement en
préproduction depuis le commit canonique Administration
`75339e533cd0139b3338e4f29c431e79c58429b4`. La release immuable
`releases/75339e5` a réussi **205 tests Node.js** et **63 tests Python** sur
Infomaniak. La sauvegarde préalable vérifiée porte l'empreinte SHA-256
`68379788dabfcd69e13f1b22cadcb254742a045e7af4f4192ba0f93ba249605b`.

Le secret de session a été renouvelé sans affichage, les anciens réglages de
session d'observation ont été retirés et les modes Administration et Suivi des
tâches restent tous deux `enforce`. Après redémarrage, `/health` répond `200`
avec `status=ok`.

La rotation a correctement invalidé l'ancienne session. Une nouvelle
authentification Infomaniak a créé une session Administration saine. L'écran
« Mes sessions » a ensuite recensé la session courante et une session Suivi des
tâches distincte. Cette dernière a été fermée à distance puis refusée par
l'application cible dès la requête suivante, avant d'être recréée proprement.

La recette a ensuite créé une seconde session Suivi des tâches réelle par le
parcours SSO normal. « Fermer toutes les autres sessions (2) » a fermé les deux
sessions Tâches en une opération, conservé la session Administration courante
et provoqué le refus immédiat du cookie Tâches au contrôle suivant. Une nouvelle
session Tâches saine a enfin été créée.

L'état final contrôlé contient une session active par application. La chaîne
d'audit est valide avec **13 créations**, **2 expirations** et **7 révocations**,
et la file locale de révocation Tâches contient **0** élément. La fermeture
groupée réelle de plusieurs sessions est donc recettée. L'isolation vis-à-vis
d'une autre identité reste couverte par les tests automatisés et attend une
seconde identité NSK Tech 09 réelle pour sa recette humaine. Aucune mutation
n'a été effectuée en production ni dans N09 – Énergie.
