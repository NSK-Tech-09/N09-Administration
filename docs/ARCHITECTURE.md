# Architecture fondatrice

## Composants cibles

```text
Portail / Applications
        |
        v
auth.nsktech.fr  ---- identité, authentification, session, OIDC
        |
        v
N09 – Administration ---- catalogue, affectations, délégations, audit
        |
        +---- événements de révocation / expiration
        |
        +---- service central de notifications

Applications métier ---- catalogue et contrôle des règles métier
```

## Frontières

Administration possède l’identifiant central, le profil commun, l’état du
compte, le registre des applications, les affectations contextualisées — sujet,
application, rôle, périmètre, conditions et dates — ainsi que leurs décisions et
leur audit.

Une application possède ses données métier, publie son catalogue versionné de
rôles, permissions et types de périmètres, interprète ses conditions et contrôle
côté serveur les droits effectifs reçus du système central.

## Authentification cible

- OpenID Connect, flux Authorization Code avec PKCE ;
- audience distincte pour chaque application ;
- validation serveur de l’émetteur, de l’audience, de la signature et des dates ;
- MFA obligatoire pour les comptes privilégiés et réauthentification sensible ;
- aucun secret collecté par les applications et aucun jeton partagé entre elles.

Le noyau ne réimplémente pas la cryptographie d’un fournisseur d’identité. N09 –
Administration est distinct du service d’identité : l’interface peut être
indisponible sans empêcher l’authentification centrale de fonctionner.

## Disponibilité

Les applications peuvent conserver une session courte après validation. Les
révocations critiques sont propagées et recontrôlées dans un délai borné. Aucune
nouvelle autorisation n’est accordée si l’intégrité de la décision centrale ne
peut pas être vérifiée.
