
# Lot 51 — Gestion personnelle des sessions

Statut : **publié, déployé et recetté en préproduction après le lot 50**

Date : **13 août 2026**

## Objet

Ce lot applique l'étape 6 de `ADR-020`. Une personne authentifiée peut consulter
ses propres connexions à l'écosystème NSK Tech 09 depuis N09 – Administration,
fermer une session distante précise ou fermer toutes ses autres sessions
actives. Il ne crée aucun pouvoir opérateur et ne modifie ni la production, ni
N09 – Énergie.

## Interface personnelle

La page `/account/sessions` indique, pour chaque session appartenant à l'identité
courante :

- l'application, le contexte compréhensible et l'état ;
- la date d'ouverture, la dernière activité et l'échéance absolue ;
- le caractère actuel de la session.

Elle n'affiche ni cookie, ni secret, ni empreinte de secret, ni adresse réseau,
ni identifiant technique de session. La session courante se ferme uniquement
par la déconnexion normale afin de préserver le contrat de déconnexion
opposable.

## Actions et protections

- toute mutation exige la session centrale active et le jeton CSRF de la
  personne ;
- la cible d'une fermeture individuelle voyage dans un jeton chiffré et
  authentifié valable dix minutes, lié à l'identité et à la version observée ;
- le serveur recherche toujours la cible dans les seules sessions de
  l'identité authentifiée ;
- une cible étrangère, courante, expirée, révoquée, altérée ou modifiée en
  concurrence est refusée ;
- « fermer toutes les autres sessions » sélectionne côté serveur les seules
  sessions encore actives et ne dépend d'aucune liste fournie par le navigateur.

La fermeture groupée est atomique. Les lignes sont verrouillées dans un ordre
stable et toutes les versions sont vérifiées avant la première modification. Si
une seule vérification échoue, aucune session n'est fermée et aucun audit
partiel n'est conservé.

## Audit et minimisation

Chaque session effectivement fermée produit son propre événement
`application_session.revoked` dans le journal central, avec l'identité agissant
pour elle-même et une cause fixe compréhensible. La mutation et l'audit sont
enregistrés dans la même transaction. Les identifiants complets de session,
cookies, secrets et empreintes restent exclus du journal.

Les sessions déjà expirées ou déjà fermées restent visibles à titre explicatif,
mais ne sont pas remaniées par une fermeture groupée. Le lot n'ajoute aucune
table et ne supprime aucune preuve existante.

## Publication et déploiement préproduction

1. Fusionner et déployer d'abord le lot 50, qui impose le format de cookie
   versionné et la nouvelle connexion.
2. Publier le lot 51 depuis un commit immuable et exécuter toute la validation
   locale et continue.
3. Sauvegarder la configuration et la base Administration sans afficher leurs
   valeurs sensibles, puis vérifier l'export et son empreinte.
4. Déployer une release immuable de N09 – Administration sans migration de base.
5. Ouvrir au moins une session Administration et une session Suivi des tâches
   pour la même identité, puis vérifier leur présence dans « Mes sessions ».
6. Fermer la session Suivi des tâches depuis Administration et vérifier son
   refus au prochain contrôle serveur, sans effet sur la session courante.
7. Recréer plusieurs sessions, utiliser « fermer toutes les autres sessions »
   et vérifier l'absence de succès partiel ainsi que la chaîne d'audit.
8. Vérifier qu'une autre identité ne voit et ne peut modifier aucune de ces
   sessions.

Les preuves de recette contiennent seulement les commits, dates, états,
compteurs et codes HTTP. Elles excluent toute valeur de cookie, tout secret,
toute empreinte et tout identifiant complet de session.

## Retour arrière

Le retour arrière réactive seulement la release applicative précédente. Il ne
restaure pas la base, ne supprime aucun événement d'audit et ne ressuscite
aucune session révoquée. Les secrets rotés au lot 50 restent inchangés. En cas
d'indisponibilité du registre, l'accès demeure fermé conformément à `ADR-020`.

## Critères d'acceptation

- seules les sessions de l'identité authentifiée sont présentées ;
- la session courante est identifiable et ne peut être fermée à distance ;
- une autre session peut être fermée avec contrôle CSRF, cible scellée et
  version optimiste ;
- toutes les autres sessions actives peuvent être fermées atomiquement ;
- les sessions expirées, révoquées ou étrangères ne sont pas modifiées ;
- chaque fermeture est auditée atomiquement et la chaîne reste valide ;
- aucun identifiant technique ni secret n'apparaît dans la page ou l'audit ;
- production et N09 – Énergie restent inchangées.

## Avancement réel du 13 août 2026

La page `/account/sessions` est déployée dans la release Administration
`releases/75339e5`. La recette réelle a confirmé :

- présentation de la session Administration courante et de la session distante
  Suivi des tâches, sans cookie, secret, adresse réseau ni identifiant technique
  de session ;
- fermeture individuelle de la session Suivi des tâches depuis Administration,
  sans effet sur la session courante ;
- passage immédiat de la cible à l'état « Fermée », puis refus effectif par
  Suivi des tâches au prochain contrôle serveur ;
- recréation d'une session Tâches saine et accès nominal aux données ;
- création successive de deux sessions Tâches réelles par le parcours SSO
  normal, toutes deux visibles comme actives depuis Administration ;
- fermeture atomique des deux sessions par « Fermer toutes les autres sessions
  (2) », sans fermer la session Administration courante ;
- refus du cookie Tâches au contrôle serveur suivant, puis recréation d'une
  session saine ;
- chaîne d'audit valide avec **13 créations**, **2 expirations** et **7
  révocations**, et file de révocation Tâches vide ;
- état final composé d'une session active par application.

La fermeture groupée atomique est ainsi recettée avec plusieurs sessions
centrales réelles, sans manipulation de cookie ni donnée artificielle. Les
refus de cible étrangère ou altérée et les concurrences restent validés par la
suite automatisée de la release immuable. La vérification humaine de
l'isolation entre deux identités distinctes nécessite encore une seconde
identité NSK Tech 09 réelle ; aucune identité fictive n'a été introduite pour
contourner cette limite de preuve.

## Références

- `ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`
- `LOT-50-FERMETURE-ANCIENNES-SESSIONS-PREPROD.md`
- `ARC-008`, `ARC-010`, `ARC-012`, `ARC-013`, `ARC-016`
- `ERG-016`, `ERG-032`, `TST-001`
