# Contrat de raccordement OIDC

## Objet

Ce contrat définit la frontière commune entre N09 – Administration et un
fournisseur OpenID Connect. Infomaniak sera le premier raccordement, mais le
code ne contient aucune règle spécifique qui le rendrait obligatoire.

## Parcours retenu

Le navigateur utilise Authorization Code avec PKCE S256. Chaque tentative
génère un `state`, un `nonce` et un vérificateur PKCE aléatoires. La preuve
temporaire est chiffrée, limitée à dix minutes, placée dans un cookie
`Secure`, `HttpOnly` et `SameSite=Lax`, puis supprimée au premier retour.

Au retour, l'adaptateur réseau :

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

## État de l'adaptateur

Le noyau reste volontairement indépendant du transport et de la cryptographie.
Le service Node de référence réalise le flux Authorization Code avec PKCE et
valide la signature RS256 avec le JWKS du fournisseur avant de vérifier `iss`,
`aud`, `sub`, `exp`, `iat`, `nonce` et `state`. La session de preuve locale est
chiffrée par AES-256-GCM et n'accorde aucun privilège : une identité externe non
rattachée porte exclusivement l'état `link_required`.

La passerelle PHP isolée a uniquement servi à éprouver le retour HTTPS et la
consultation en lecture seule du registre sur l'hébergement existant. Comme
elle interroge `userinfo` sans valider la signature du jeton d'identité, elle ne
peut créer ni session NSK, ni compte, ni rattachement, ni droit. Elle n'est pas
l'adaptateur OIDC de référence.
