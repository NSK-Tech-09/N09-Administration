# Lot 46 — Activation contrôlée de l'observation des sessions en préproduction

Statut : **préparé localement ; préproduction constatée en lecture seule ; aucune migration ni activation effectuée**

Date : **13 août 2026**

## Objet

Ce lot prépare l'activation réelle, mais toujours inopposable, du registre de
sessions de N09 – Administration. Il applique la deuxième étape de `ADR-020`
sans ouvrir l'étape d'opposabilité.

Le commit de code fusionné à déployer est le commit de fusion de la PR #47 :
`4d4284b26d9a64fb696cfac719e3e8e064a10a4c`.

## Constat initial en lecture seule

Le 13 août 2026, la base réelle `6p7h3x_n09_admin_preprod` a été consultée dans
phpMyAdmin sans écriture. Les tables des lots précédents, dont
`notification_processing_state`, sont présentes. La table
`application_sessions` est absente de la structure visible.

Ce constat correspond à la frontière documentée par les lots 43 à 45 : le
schéma et le comportement sont fusionnés, mais rien n'a encore été installé ou
activé sur Infomaniak.

Le terminal SSH de l'hébergement exact **N09 - Cœur et Administration** confirme
également :

- site `/srv/customer/sites/preprod-admin.nsktech.fr` ;
- commande active pointant sur `releases/3338ea8` ;
- sept marqueurs de démarrage du lot 41 tous exigés avant lancement ;
- release `releases/3338ea8` intacte avec ses preuves, dont tests, sauvegarde,
  schéma, intégrité, cycle manuel et fermeture des canaux externes ;
- `N09_ENVIRONMENT=preprod` ;
- `N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY=false` ;
- absence de `N09_SESSION_SHADOW_MODE`, donc mode `disabled` par défaut ;
- plusieurs releases antérieures conservées, notamment `releases/7813eca`.

Le fichier `VERSION` actuellement à la racine porte une ancienne empreinte de
construction et ne constitue pas la preuve d'activation. La source d'autorité
est la commande Node.js visible dans le gestionnaire, qui cible explicitement
`releases/3338ea8`. Le lot ne réutilisera donc pas `VERSION` comme garde-fou.

## Invariants non négociables

- environnement exact : `preprod` ;
- base exacte : `6p7h3x_n09_admin_preprod` ;
- mode exact : `observe` ;
- aucune valeur `enforce` ou équivalente ;
- canaux externes de notification maintenus fermés ;
- sauvegarde logique vérifiée avant création de table ;
- release immuable et release précédente conservées ;
- compte DDL séparé du compte d'exécution ;
- aucun secret, cookie, identifiant de session ou empreinte dans les preuves ;
- aucune modification de production.

## Séquence préparée

### 1. État avant intervention

Consigner :

- commit et release réellement actifs ;
- commande de démarrage actuelle ;
- résultat de `GET /health` ;
- mode de session actuel, attendu `disabled` ou absent ;
- absence de `application_sessions` ;
- validité de la chaîne d'audit ;
- fermeture de tous les canaux externes.

### 2. Sauvegarde

Créer un export logique sous
`/srv/customer/backups/preprod-admin/lot46-pre-session-shadow-<UTC>.sql.gz`.

Avant de continuer, consigner : taille non nulle, test gzip réussi, empreinte
SHA-256 et fin d'export MariaDB. Une sauvegarde présente mais non vérifiée ne
compte pas comme point de retour.

### 3. Migration additive

Exécuter avec l'identité DDL dédiée :

`service-node/mariadb/migrations/20260813-application-sessions.sql`

Puis exécuter le fichier de contrôles associé. Les résultats attendus sont :

- une table InnoDB ;
- 15 colonnes ;
- 4 index distincts ;
- 3 clés étrangères ;
- zéro session avant la première connexion de recette.

Le compte d'exécution doit ensuite prouver qu'il peut lire et écrire les lignes
de cette table sans disposer du droit `CREATE`.

### 4. Release immuable

Construire une release depuis le commit exact fusionné, installer ou reprendre
les dépendances uniquement après vérification des empreintes de
`package.json` et `pnpm-lock.yaml`, puis exécuter les suites complètes sur
Infomaniak.

La commande de lancement doit rester conditionnée par les marqueurs existants
de sauvegarde, schéma, tests, intégrité, aptitude au déploiement et fermeture
des canaux externes.

### 5. Activation bornée

Ajouter explicitement à la préproduction :

```text
N09_ENVIRONMENT=preprod
N09_SESSION_SHADOW_MODE=observe
N09_SESSION_SHADOW_IDLE_TTL_MS=1800000
N09_SESSION_SHADOW_ABSOLUTE_TTL_MS=28800000
N09_SESSION_SHADOW_TOUCH_INTERVAL_MS=300000
```

Redémarrer uniquement après réussite de tous les garde-fous. Le journal de
démarrage doit annoncer `session_shadow_mode=observe` sans autre donnée de
session.

### 6. Recette réelle

1. vérifier `GET /health` ;
2. fermer la session Administration existante ;
3. ouvrir une nouvelle connexion Infomaniak rattachée ;
4. vérifier qu'une seule session centrale active a été créée ;
5. vérifier un audit `application_session.created` sans référence ni empreinte ;
6. effectuer plusieurs lectures protégées ;
7. vérifier que l'activité n'est consolidée qu'après cinq minutes ;
8. vérifier que les accès et droits actuels restent inchangés ;
9. vérifier que Suivi des tâches et la production restent inchangés.

La recette ne doit afficher, copier ou conserver ni secret brut, ni empreinte,
ni contenu du cookie.

## Retour arrière

Le retour arrière immédiat consiste à restaurer la release et la commande de
lancement précédentes, ou à remettre `N09_SESSION_SHADOW_MODE=disabled`, puis à
redémarrer et contrôler `/health`.

La table additive n'est pas supprimée pendant le retour arrière : l'ancienne
release l'ignore et sa conservation évite une suppression de preuve. Une
restauration de base n'est envisagée qu'en cas de corruption indépendante,
après décision humaine explicite.

## Critères d'arrêt

Arrêt immédiat avant bascule si :

- la sauvegarde n'est pas vérifiable ;
- la cible n'est pas exactement la base de préproduction Administration ;
- la migration produit un schéma différent des comptes attendus ;
- le compte d'exécution dispose de droits DDL ;
- un test échoue ;
- un canal externe est ouvert ;
- la release précédente ou la commande de retour arrière n'est pas disponible.

Après bascule, revenir au mode `disabled` si le service ne démarre pas, si la
santé n'est pas `200`, si une donnée sensible apparaît dans les journaux ou si
le comportement d'accès change.

## Preuves à compléter après exécution

- fichier, taille et SHA-256 de la sauvegarde : **à compléter** ;
- release précédente : **`releases/3338ea8`, constatée intacte avec ses marqueurs** ;
- release activée : **à compléter** ;
- tests exécutés sur Infomaniak : **à compléter** ;
- résultat des contrôles de schéma : **à compléter** ;
- première session et audit observés sans donnée sensible : **à compléter** ;
- résultat du retour arrière à blanc : **à compléter**.

## Références

- `ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`
- `LOT-43-SOCLE-REGISTRE-SESSIONS.md`
- `LOT-44-PERSISTANCE-AUDIT-SESSIONS.md`
- `LOT-45-OBSERVATION-INOPPOSABLE-SESSIONS.md`
- PR GitHub `NSK-Tech-09/N09-Administration#47`
