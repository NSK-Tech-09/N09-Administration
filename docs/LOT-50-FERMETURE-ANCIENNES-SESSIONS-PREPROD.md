# Lot 50 — Fermeture des anciennes sessions en préproduction

Statut : **implémenté et validé localement ; déploiement préproduction à exécuter**

Date : **13 août 2026**

## Objet

Ce lot applique l'étape 5 de `ADR-020` après l'opposabilité recettée des
sessions d'Administration et de Suivi des tâches. Il ferme la fenêtre de
compatibilité avec les cookies autonomes et impose une nouvelle connexion.
Il ne modifie ni la production, ni N09 – Énergie.

## Contrat fermé

- tout nouveau cookie Administration porte `sessionVersion=2` ;
- tout cookie Administration absent de cette version est refusé avant
  consultation du registre ;
- seule `centralSession` est comprise : l'ancien champ `shadowSession` n'est
  plus lu ;
- les anciens réglages `N09_SESSION_SHADOW_*` sont ignorés ;
- Suivi des tâches exige à la connexion une session centrale complète avant
  d'émettre son cookie, puis exige `sessionVersion=2` et la preuve centrale à
  chaque requête protégée ;
- aucun ancien cookie n'est converti, prolongé ou inscrit silencieusement.

Les enregistrements historiques et leur audit restent conservés. Ce lot ne
supprime aucune session ni aucune preuve en base.

## Déploiement préproduction

1. Identifier les commits immuables et conserver les releases du lot 49 comme
   points de comparaison.
2. Sauvegarder les deux fichiers d'environnement avec permissions restreintes,
   sans afficher leurs valeurs.
3. Sauvegarder les deux bases, vérifier gzip, fin d'export et SHA-256.
4. Construire les deux releases depuis les commits retenus et exécuter leurs
   suites de tests avant changement de lien actif.
5. Remplacer indépendamment `N09_SESSION_SECRET` dans Administration et Suivi
   des tâches par deux valeurs aléatoires nouvelles d'au moins 32 caractères.
   Ne jamais les copier dans un journal, une preuve ou Git.
6. Conserver `N09_ADMIN_SESSION_MODE=enforce` et le contrôle central Tâches en
   mode opposable ; supprimer des fichiers actifs les anciens réglages
   `N09_SESSION_SHADOW_*` devenus sans effet.
7. Activer d'abord Administration, contrôler sa santé et son démarrage, puis
   activer Suivi des tâches et contrôler sa santé.
8. Vérifier qu'un navigateur possédant les anciens cookies est renvoyé vers la
   connexion dans les deux applications.
9. Effectuer une nouvelle authentification Infomaniak dans chaque application,
   vérifier l'accès nominal et l'apparition d'une seule nouvelle session
   centrale par application.
10. Vérifier la déconnexion opposable, le refus d'une copie de l'ancien cookie,
    la file de révocation Tâches à zéro et la chaîne d'audit valide.

Les preuves ne contiennent que les commits, états, compteurs, dates, empreintes
de sauvegardes et codes HTTP. Elles excluent cookies, secrets, empreintes de
secrets et identifiants complets de session.

## Retour arrière sans résurrection

Un retour arrière applicatif conserve impérativement les **nouveaux** secrets
de cookie. Restaurer les anciens secrets réactiverait des copies historiques et
est donc interdit. La release précédente peut être réactivée uniquement après
vérification qu'elle fonctionne avec les nouveaux secrets et avec les modes
centraux opposables.

Ne jamais supprimer `application_sessions`, la file de révocation Tâches, ni
les événements d'audit. Si l'autorité centrale n'est pas vérifiable, l'accès
reste fermé et le diagnostic est poursuivi sans bascule vers une session
autonome.

## Critères d'acceptation

- anciens cookies refusés dans les deux applications ;
- nouvelle connexion obligatoire et fonctionnelle ;
- nouvelle session centrale créée et contrôlée pour chaque application ;
- déconnexion et révocation toujours opposables ;
- aucune résurrection après simulation du retour arrière ;
- aucun secret dans les traces ;
- production et N09 – Énergie inchangées.

## Références

- `ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`
- `LOT-49-DEPLOIEMENT-SESSIONS-OPPOSABLES-PREPROD.md`
- N09 – Suivi des tâches : `LOT-41-FERMETURE-ANCIENNES-SESSIONS.md`
- `ARC-008`, `ARC-010`, `ARC-012`, `ARC-013`, `ARC-016`
- `ERG-016`, `ERG-032`, `TST-001`
