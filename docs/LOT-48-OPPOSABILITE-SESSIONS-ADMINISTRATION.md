# Lot 48 — Opposabilité des sessions dans N09 – Administration

Statut : **implémenté et validé localement, non publié et non déployé**

Date : **13 août 2026**

## Objet

Ce lot prépare la quatrième étape de `ADR-020` : rendre le registre central
opposable à la propre session web de N09 – Administration. Il prolonge sans la
court-circuiter l'observation recettée au lot 46. Il ne ferme pas encore la
fenêtre de compatibilité des cookies créés pendant cette observation.

## Autorité de session Administration

Une autorité dédiée porte désormais trois modes :

- `disabled`, fermé par défaut ;
- `observe`, identique au comportement inopposable déjà recetté ;
- `enforce`, qui exige une session centrale active avant toute utilisation de
  la session web Administration.

Le retour OIDC validé crée la session centrale avant d'émettre le cookie. En
mode opposable, une impossibilité d'enregistrement répond `503` et aucun cookie
local autonome n'est créé.

Chaque ouverture du cookie vérifie ensuite la référence, le secret, l'identité,
l'application, la révocation et les deux échéances. Une preuve absente,
incohérente, expirée, révoquée ou invérifiable ferme l'accès. L'activité reste
consolidée au plus toutes les cinq minutes ; un conflit de consolidation relit
le registre avant de poursuivre.

## Déconnexion confirmée

En mode `enforce`, la déconnexion révoque d'abord la session centrale avec
l'identité courante comme acteur, puis efface le cookie. Si la révocation ne
peut pas être confirmée, la réponse est `503`, le cookie n'est pas effacé et
l'interface ne présente aucun succès fictif. L'utilisateur peut ainsi réessayer
sans laisser derrière lui une session réputée fermée seulement dans le
navigateur.

## Compatibilité bornée

Les cookies issus de l'observation contiennent encore la preuve sous le nom
interne `shadowSession`. Le contrôle accepte temporairement cette propriété et
la nouvelle propriété `centralSession` afin que les sessions réellement
enregistrées au lot 46 puissent être recettées sans bascule brutale.

Les anciennes variables `N09_SESSION_SHADOW_*` restent lues uniquement comme
solution de transition. Les variables canoniques deviennent :

- `N09_ADMIN_SESSION_MODE` ;
- `N09_ADMIN_SESSION_IDLE_TTL_MS` ;
- `N09_ADMIN_SESSION_ABSOLUTE_TTL_MS` ;
- `N09_ADMIN_SESSION_TOUCH_INTERVAL_MS`.

La suppression de l'alias et la rotation qui invalidera les cookies dépourvus
de preuve relèvent explicitement de l'étape 5 de `ADR-020`.

## Validation locale

- contrôle opposable d'une session active, absente, altérée, révoquée ou
  indisponible ;
- création stricte en `enforce` et tolérante uniquement en `observe` ;
- consolidation bornée avec relecture après conflit ;
- révocation atomique et auditée avant suppression du cookie ;
- conservation du cookie et réponse `503` si la fermeture centrale échoue ;
- absence de secret et de référence complète dans l'audit et les journaux ;
- compatibilité de lecture des sessions d'observation existantes.

## Activation préparée

La préproduction doit rester en `observe` tant que le lot 47 n'est pas fusionné,
déployé et recetté pour l'application pilote. La bascule Administration suit
ensuite cette séquence : sauvegarde vérifiée, release immuable, variables
canoniques en `observe`, nouvelle connexion de contrôle, puis passage à
`enforce` avec retour arrière immédiat vers `observe`.

Aucune variable distante, migration, release ou donnée n'est modifiée par le
présent lot local. La production reste inchangée.

## Références

- `ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`
- `LOT-46-ACTIVATION-OBSERVATION-SESSIONS-PREPROD.md`
- `LOT-47-OPPOSABILITE-SESSIONS-SUIVI-TACHES.md`
- `ARC-008`
- `ARC-010`
- `ARC-013`
- `ERG-016`
- `ERG-032`
- `TST-001`
