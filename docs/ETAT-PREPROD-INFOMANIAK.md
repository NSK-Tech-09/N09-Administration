

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

## Lot 52 — seconde identité humaine et isolation réelle validées

Le **13 août 2026**, une seconde identité humaine active a été créée par la
commande contrôlée de préproduction, sans affectation ni permission :

- **Fred TRAVERS — Recette** ;
- `travers.fred.09@gmail.com` ;
- identité NSK `ac31d4fa-ca3f-4d34-87b3-3d8e436b30de` ;
- chaîne d'audit valide ;
- zéro droit actif après création.

La première connexion réelle dans une session Chrome isolée a produit une
demande `link_required`, sans création automatique de compte ou de droit.
L'identité administratrice principale a approuvé cette demande vers l'identité
de recette avec une justification explicite. Le registre a alors conservé les
six affectations existantes exclusivement sur l'identité principale.

La recette a découvert un défaut de renouvellement : la fermeture d'une session
encore `link_required` exigeait à tort la révocation d'une session centrale qui
n'existe pas à ce stade. La PR **#59** a corrigé ce cas tout en conservant la
révocation centrale obligatoire pour les sessions réellement authentifiées.
Elle a été fusionnée avec le commit
`16399df2b53a009d2592c3511be7fa7055d43d0a`.

La release immuable `releases/16399df` a réussi **211 tests Node.js** et
**63 tests Python** sur Infomaniak. Après un redémarrage explicite du processus,
les contrôles local et public de `/health` ont répondu `{"status":"ok"}`.
La release précédente `releases/dbf951a` reste disponible pour retour arrière.

La recette finale dans Chrome confirme que :

- la déconnexion puis la reconnexion du compte de recette fonctionnent ;
- l'identité est affichée comme rattachée sous **Fred TRAVERS — Recette** ;
- `/admin/access` est refusé faute de permission dédiée ;
- N09 – Suivi des tâches refuse la connexion faute d'autorisation centrale ;
- l'identité de recette ne voit que sa propre session Administration ;
- aucune session de l'identité principale, aucun rôle et aucun droit ne sont
  exposés ou accordés implicitement.

L'isolation humaine réelle attendue après les lots 50 et 51 est donc validée.
Aucune modification n'a été effectuée en production ni dans N09 – Énergie.

## Lot 53 — révocation opérateur des sessions déployée

Le **13 août 2026**, le commit canonique
`0e01ac1a4756704f7ea2fd41031912e67491df10` a été déployé dans la release
immuable `releases/0e01ac1`. L'archive complète porte l'empreinte SHA-256
`bc7a51dfa2973d2cbb55b96fd30926968f8aa3cd9e24641b8e69cf836aec99be` ;
**183 fichiers**, **223 tests Node.js** et **63 tests Python** ont été validés
sur Infomaniak avant le gel du dossier.

La sauvegarde préalable
`/srv/customer/backups/preprod-admin/lot53-pre-operator-session-revocation-20260813T173642Z.sql.gz`
pèse **28 412 octets** et porte l'empreinte
`0b56debebfe68f2f3304b5a8031fda46f9ba4313a732bceee67cc64c619b8892`.
Elle est valide au format gzip et sa fin d'export est présente. Les
déclencheurs, refusés au compte d'exécution sans privilège `TRIGGER`, restent
versionnés dans le schéma de la release et n'ont pas été modifiés.

Le catalogue Administration v4 est publié avec l'empreinte
`4598c3412bba808c149abf9bf83241c26037fdf61ce560320accd315c1c94f9a`.
La route `/admin/sessions` a d'abord refusé l'identité principale faute de
permission, puis l'amorçage préproduction audité a ajouté le seul rôle
`session-revocation-administrator` à Fred TRAVERS.

La recette réelle a révoqué une session N09 – Suivi des tâches distincte avec
justification. Tâches a refusé cette session à la requête suivante et une
reconnexion SSO propre a recréé une session saine. La session Administration
courante n'était pas révocable depuis la console. L'audit final contient la
révocation en succès et `verifyAuditChain()` renvoie `true`.

Les contrôles local et public de `/health` répondent `200` avec
`{"status":"ok"}`. Le registre central, l'exploitation des notifications et
N09 – Suivi des tâches restent opérationnels ; tous les canaux externes sont
fermés. `releases/16399df` et `releases/dbf951a` restent disponibles pour le
retour arrière. Aucun changement n'a touché la production ni N09 – Énergie.

## Lot 54 — suspension atomique des identités déployée

Le **13 août 2026**, le commit canonique
`551db4b4725ca61d591d8e1376924421c3ded024` a été activé dans la release
immuable `releases/551db4b`. L’archive porte l’empreinte SHA-256
`2cccb8152043ff9d7231a9c94a3fc45c3a53e2b874aef265d526b8f3127b5181` ;
**190 fichiers**, **236 tests Node.js** et **63 tests Python** ont été validés
sur Infomaniak avant le gel en lecture seule.

La sauvegarde préalable
`/srv/customer/backups/preprod-admin/lot54-pre-identity-suspension-20260813T185145Z.sql.gz`
pèse **31 283 octets**, est valide au format gzip et porte l’empreinte
`6d325682b4da14bc25cf0c24497d0d7138f5bc10d71f503edf4a23fef548a01c`.
Le catalogue Administration v5 est publié avec l’empreinte
`fe48460d21d7a6239c23d96ac0875999759c9c5e10bbffd9913627c89a45115e`
et l’identité principale possède l’affectation gouvernée
`identity-suspension-administrator`.

La nouvelle console `/admin/identities` refuse l’auto-suspension. La recette
réelle a créé une session éphémère auditée pour l’identité **Fred TRAVERS —
Recette**, puis l’a suspendue depuis l’interface. Le résultat contrôlé est
`suspended`, zéro session active, une session révoquée ; les événements
`identity.suspended` et `application_session.revoked` partagent la même
corrélation et la chaîne d’audit reste valide. L’identité principale demeure
active avec ses deux sessions.

Le garde-fou de démarrage a refusé une première tentative à cause d’un marqueur
de provenance mal placé, sans laisser démarrer une version incomplète. Après
correction et nouveau contrôle, le service est actif sur `releases/551db4b`,
`/health` répond `200`, le worker interne est sain et les canaux externes restent
fermés. `releases/0e01ac1` et la sauvegarde du lot 54 sont conservés pour retour
arrière. La production et N09 – Énergie n’ont pas été modifiées.

## Lot 55 — réactivation gouvernée des identités déployée

Le **13 août 2026**, le commit canonique
`5d64bc17e5b27cf31b242450b7b8b5850b8de9c0` a été activé dans la release
immuable `releases/5d64bc1`. L’archive porte l’empreinte SHA-256
`258db8933ca3b79091d6f17fefda04524a28c5c369cf78adce5d2904ef451c7c` ;
**192 fichiers source**, **242 tests Node.js** et **63 tests Python** ont été
validés sur Infomaniak avant le gel en lecture seule.

La sauvegarde préalable
`/srv/customer/backups/preprod-admin/lot55-pre-identity-reactivation-20260813T213558Z.sql.gz`
pèse **32 921 octets**, est valide et porte l’empreinte
`47237d701af58da710c82f95b13d626f36b51b53194372442b22a18e727884`.
Le catalogue Administration v6 est publié avec l’empreinte
`23be37690476002a7b79e58a8fb17e7127a39ce30b530804cfdc99fe5bed3a33`
et l’identité principale possède l’affectation gouvernée
`identity-reactivation-administrator`.

La recette a détecté que l’enregistrement de la nouvelle commande Infomaniak
n’avait pas remplacé le processus déjà en mémoire. Elle n’a déclenché aucune
transition métier avant le redémarrage explicite. Le lot 55 actif a ensuite
réactivé **Fred TRAVERS — Recette** depuis `/admin/identities`, avec une
justification humaine.

Le résultat contrôlé est `active`, avec **0 session active** et **0 ancienne
session restaurée**. La session révoquée par le lot 54 reste révoquée,
l’événement `identity.reactivated` est présent et la chaîne d’audit est valide.
`/health` répond `200`, l’administration anonyme répond `401`, le worker interne
termine son cycle sans erreur ni quarantaine et les émissions externes restent
fermées.

La preuve scellée
`/srv/customer/backups/preprod-admin/lot55-recipe-20260813T2200Z.txt` est
protégée en mode `600` et porte l’empreinte
`4928140aa32c7d29f208bdb791c4640050e8927b004b98bd0ad2de4962395a19`.
`releases/551db4b` et la sauvegarde du lot 55 restent disponibles pour retour
arrière. La production et N09 – Énergie n’ont pas été modifiées.

## Lot 56 — désactivation gouvernée des identités déployée

Le **14 août 2026**, le commit canonique
`c0c260155a359993b2cea9e23e2ae30dabab1aac` a été activé dans la release
immuable `releases/c0c2601`. L’archive porte l’empreinte SHA-256
`d139ea4a897b3a77a458dae6c85449733ff47acee765e83e3ef5c8b2396b987d` ;
**194 fichiers source**, **250 tests Node.js** et **63 tests Python** ont été
validés sur Infomaniak.

La sauvegarde préalable
`/srv/customer/backups/preprod-admin/lot56-pre-identity-disablement-20260814T051834Z.sql.gz`
pèse **34 168 octets**, est valide, protégée en mode `600` et porte l’empreinte
`2ea373936bfd21acd1c38a78451c939dd9505b0f74c910d1b3936c388c982974`.
Le catalogue Administration v7, d’empreinte
`b06c3253693cf3e72013dff121f458846dc3a32e059d5c36b2da490a0af2ed13`,
et l’affectation `identity-disablement-administrator` ont chacun passé un second
amorçage idempotent avec chaîne d’audit valide.

Le premier redémarrage proposé par Infomaniak a conservé le processus du lot 55
en mémoire. Le contrôle de l’interface a empêché toute recette sur cette version
ancienne. Un arrêt et un démarrage explicites ont chargé `releases/c0c2601` ;
`/health` répond `{"status":"ok"}` et `/admin/identities` expose le pouvoir
`administration:identities:disable` tout en refusant l’auto-désactivation.

La recette finale a créé l’identité jetable
`70b77ba9-4dbb-49e3-b8ee-e677df2a89ed`, sans droit implicite, puis lui a accordé
temporairement `tasks-reader` sur `site_lot56_disablement_recipe`. Sa
désactivation depuis la console a produit l’état `disabled`, **0 session active**,
**0 affectation active** et **1 affectation révoquée**. L’affectation révoquée
conserve la justification de la décision et sa version 2 ; la chaîne d’audit
reste valide.

Les deux identités humaines existantes restent actives et inchangées. La preuve
scellée
`/srv/customer/backups/preprod-admin/lot56-disablement-recipe-proof-20260814T055123Z.txt`
est protégée en mode `600` et porte l’empreinte
`234139ceeda169ab0dcf4d914ceb7d02f8031c1c0648048bca88f1c3b5a2bfea`.
`releases/5d64bc1` reste disponible pour retour arrière. La production et
N09 – Énergie n’ont pas été modifiées.
