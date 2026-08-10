# ADR-006 – Transport HTTP interne fermé par défaut

Statut : **Acceptée pour validation isolée, non déployée**
Date : **10 août 2026**

## Contexte

Le noyau Node et l'adaptateur MariaDB savent calculer une décision d'accès, mais
aucun transport réseau ne doit contourner la future validation OIDC ni exposer
les détails internes du service.

## Décision

Le premier transport utilise le serveur HTTP natif de Node.js 24 et une seule
route métier : `POST /internal/v1/access-decisions`. L'authentification est une
dépendance injectée. En son absence, toute décision est refusée avec `401` ;
aucun en-tête fourni directement par un appelant n'est considéré comme une
identité ou une audience fiable.

Le transport impose JSON, limite le corps à 64 Kio, conserve les codes du contrat
interne et renvoie un identifiant de corrélation sans détail de panne. La route
`GET /health` expose uniquement un état minimal. Les réponses ne sont jamais
mises en cache et interdisent l'interprétation approximative de leur type.

Le jeu de validation associé utilise exclusivement le domaine réservé
`example.invalid`, des UUID reconnaissables et une application synthétique. Son
amorçage exige un indicateur explicite et une base dont le nom se termine par
`_preprod`. Chaque création reste auditée et l'opération est idempotente.

Les points d'entrée `server.mjs` et `seed-synthetic-preprod-cli.mjs` chargent une
configuration nommée et vérifiée. TLS est obligatoire pour MariaDB. Tant que
OIDC n'est pas raccordé, le serveur écoute sur la boucle locale. Une écoute sur
`0.0.0.0` n'est admise qu'avec l'indicateur explicite de proxy de confiance
requis par le frontal HTTPS managé Infomaniak. La route de décision reste alors
anonyme et fermée avec `401`, et aucun port applicatif brut n'est ouvert.

## Limites avant déploiement

- aucun adaptateur OIDC réel n'est encore raccordé ;
- aucun serveur métier n'est lancé automatiquement ;
- aucune donnée synthétique n'est écrite sans validation préalable sur MariaDB ;
- aucune application existante n'est autorisée à appeler cette route.

## Conséquences

- le transport peut être testé sans affaiblir la frontière d'authentification ;
- la future passerelle OIDC devra fournir l'application, l'audience et la
  corrélation déjà validées ;
- un défaut de configuration reste un refus, jamais un accès implicite ;
- le déploiement et l'ouverture réseau demeurent des jalons distincts et
  réversibles.
