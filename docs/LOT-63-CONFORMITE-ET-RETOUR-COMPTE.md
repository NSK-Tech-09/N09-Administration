# Lot 63 — Conformité visuelle et retour depuis le compte

## Objet

Ce lot corrige deux écarts observés en production : la perte du contexte d'origine lors de l'ouverture du compte central et l'enveloppe visuelle incomplète de N09 — Administration.

## Retour gouverné vers l'application d'origine

La route `/portal/account` accepte désormais un paramètre `return_to` uniquement s'il désigne une origine NSK explicitement autorisée : portail, Énergie, Suivi des tâches ou Administration. Le thème demandé est limité à `system`, `light`, `gray` ou `dark`.

Ces deux valeurs sont conservées pendant l'authentification, l'affichage des sessions et les opérations de révocation. La page du compte présente ensuite un bouton de retour vers l'application d'origine. Une origine inconnue est ignorée et le repli renvoie vers le portail.

## Alignement au référentiel NSES

La coque HTML commune d'Administration fournit désormais :

- la police Manrope embarquée localement ;
- le logo officiel NSK Tech 09, sans transformation, relié au portail dans un nouvel onglet ;
- un en-tête permanent identifiant clairement l'application ;
- les accès Compte, Déconnexion et Accès rapide ;
- les quatre thèmes `system`, `light`, `gray` et `dark` ;
- un lien d'évitement, des focus visibles et une mise en page adaptative ;
- un pied de page dans l'ordre prescrit : application et version, mentions légales et confidentialité, puis slogan institutionnel ;
- des actifs statiques locaux servis sous une politique CSP restrictive.

## Limites assumées

Cette livraison met l'enveloppe commune en conformité matérielle. L'affichage contextualisé du nom et du rôle de l'utilisateur dans l'en-tête, ainsi que le filtrage individuel des raccourcis selon les droits effectifs, restent à intégrer à la prochaine évolution de la coque authentifiée. Ces points ne sont pas présentés comme déjà réalisés.

## Contrôles

Les tests HTTP vérifient le logo, la police, la navigation, les thèmes, le pied de page, la politique CSP, les actifs locaux ainsi que la préservation sûre de `return_to` et du thème.
