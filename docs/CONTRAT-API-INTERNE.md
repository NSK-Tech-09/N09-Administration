# Contrat de la première API interne

## Frontière d’authentification

L’adaptateur réseau doit fournir une application authentifiée avec une audience
validée et un identifiant de corrélation. Le noyau ne lit ni jeton ni secret :
leur validation appartient au composant OIDC placé devant cette frontière.

## Décision d’accès

L’opération `evaluate_access_request` accepte uniquement l’identité, l’application,
la permission, le périmètre et les conditions satisfaites. Une application ne
peut interroger que sa propre audience.

- absence d’authentification : `401` ;
- audience ou frontière applicative invalide : `403` ;
- entrée invalide ou champ inconnu : `400` ;
- identité ou application absente : réponse neutre `404` ;
- décision calculée : `200`, y compris lorsque l’accès est refusé.

Cette séparation évite de confondre un refus métier avec une panne du service.
Le futur transport HTTP devra conserver ces codes sans exposer de détail interne.
