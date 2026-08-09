# Contrat de raccordement OIDC

## Objet

Ce contrat définit la frontière commune entre N09 – Administration et un
fournisseur OpenID Connect. Infomaniak sera le premier raccordement, mais le
code ne contient aucune règle spécifique qui le rendrait obligatoire.

## Parcours retenu

Le navigateur utilise Authorization Code avec PKCE S256. Chaque tentative
génère un `state`, un `nonce` et un vérificateur PKCE aléatoires. Leur durée de
vie et leur usage unique seront imposés par le futur stockage de session.

Au retour, l'adaptateur réseau devra :

1. vérifier `state` avant l'échange du code ;
2. échanger le code côté serveur avec le vérificateur PKCE ;
3. vérifier cryptographiquement le JWT avec le JWKS du fournisseur ;
4. refuser tout algorithme non explicitement autorisé ;
5. transmettre seulement les claims vérifiés au noyau.

Le noyau vérifie ensuite exactement `iss`, `aud`, `sub`, `exp`, `iat` et
`nonce`. L'adresse et le nom restent des attributs facultatifs d'affichage.

## Secrets et configuration

Le `client_id` est une configuration publique. Le secret client éventuel reste
hors du dépôt, hors des journaux et hors de la base métier. Les endpoints sont
chargés depuis le document de découverte, dont l'émetteur doit correspondre
exactement à l'émetteur attendu.

## Limite actuelle

Le noyau ne télécharge pas encore le document de découverte, n'échange pas de
code et ne vérifie pas lui-même une signature JWT. Ces responsabilités seront
confiées à une bibliothèque de sécurité maintenue et testée, jamais à une
implémentation cryptographique artisanale.
