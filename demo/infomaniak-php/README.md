# Passerelle PHP d'évaluation

Cette passerelle a servi à valider sur l'hébergement Infomaniak le flux
Authorization Code avec PKCE, le retour HTTPS et la lecture seule du registre.

Elle n'est pas l'adaptateur OIDC de référence et ne doit créer ni session NSK,
ni compte, ni rattachement, ni droit. Elle interroge `userinfo` avec le jeton
d'accès obtenu côté serveur, mais ne valide pas encore la signature du jeton
d'identité. À ce titre, elle reste un banc de validation isolé.

L'adaptateur de référence est celui de `demo/app/auth/infomaniak`, qui contrôle
la signature RS256 avec le JWKS du fournisseur ainsi que `iss`, `aud`, `exp`,
`nonce`, `state` et PKCE. Toute mise en production d'une session NSK doit passer
par cette frontière conforme au contrat `docs/CONTRAT-OIDC.md`.

Les secrets et la base réelle restent hors du dépôt et hors du répertoire Web.
