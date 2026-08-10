# ADR-007 – Demandes de rattachement persistantes dans le service Node

## Décision

Le service Node de référence porte désormais le même cycle de rattachement que
le noyau Python. Une identité OIDC inconnue crée une demande temporaire
`pending`, distincte du compte NSK et distincte du futur lien d'identité.

La demande expire après quinze minutes. Une nouvelle authentification pendant
ce délai réutilise la demande active ; elle ne produit ni doublon, ni événement
d'audit artificiel. Après expiration, une nouvelle demande peut être créée.

## Garanties

- le couple exact `issuer + subject` reste la seule clé externe ;
- l'adresse électronique et le nom sont de simples indices de contrôle humain ;
- demande métier et événement d'audit sont écrits dans une même transaction ;
- l'approbation exige une identité NSK cible, un décideur et une justification ;
- le rejet ne crée aucun lien ;
- l'approbation crée le lien externe, mais aucune affectation ni aucun droit ;
- une identité externe révoquée ou une identité NSK inactive est refusée ;
- aucun jeton, secret ou contenu de session n'entre dans la base ou l'audit.

L'unicité universelle d'un lien est protégée par une empreinte SHA-256 du couple
exact `issuer + subject`. Les valeurs originales restent conservées pour la
vérification et l'exploitation ; l'empreinte évite une unicité approximative
sur des préfixes SQL.

## Limite volontaire

Ce lot ne publie pas de bouton d'approbation anonyme. La décision sera exposée
uniquement derrière une authentification administrative NSK et une délégation
explicite. Tant que cette frontière n'est pas disponible, la demande reste sans
effet et le refus par défaut demeure total.
