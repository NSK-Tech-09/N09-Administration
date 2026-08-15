# ADR-022 — Connexion par courriel sans mot de passe

## Décision

N09 – Administration peut authentifier une identité NSK déjà active au moyen
d'un lien reçu par courriel. Cette méthode est une preuve d'identité ; elle ne
crée pas de compte, ne rattache pas une identité externe et n'accorde aucun
droit.

L'adresse saisie doit correspondre exactement, après normalisation, à
l'adresse unique du registre central. Une adresse inconnue, suspendue,
désactivée ou archivée reçoit la même réponse publique qu'une adresse active,
mais aucun message n'est expédié.

## Propriétés de sécurité

- le secret contient 256 bits aléatoires et voyage uniquement dans le lien ;
- MariaDB conserve seulement son empreinte SHA-256 ;
- le lien expire après dix minutes et devient inutilisable dès sa première
  consommation ;
- l'ouverture du lien ne le consomme pas : une confirmation locale en `POST`
  protège l'utilisateur contre les robots d'analyse des messageries ;
- entre ouverture et confirmation, le secret est enfermé dans un cookie
  chiffré, `HttpOnly`, `Secure`, `SameSite=Lax` et limité au chemin concerné ;
- la consommation est verrouillée et atomique avec son événement d'audit ;
- trois demandes au plus par heure sont acceptées pour une même combinaison
  d'origine réseau et d'adresse ;
- la réponse valable est volontairement temporisée et identique pour limiter
  l'énumération des comptes ;
- un échec de remise invalide immédiatement la demande et produit un audit
  sans adresse, secret ni lien ;
- la destination de retour reste locale à Administration et limitée à la
  liste blanche déjà utilisée par le courtage applicatif ;
- la session centrale obtenue est la même que pour Infomaniak et reste soumise
  au registre opposable de sessions ;
- aucun mot de passe NSK n'est créé ou stocké.

## Livraison du message

Le premier adaptateur utilise l'API de courriel transactionnel Brevo. Il est
isolé derrière le contrat `delivery.send` afin de pouvoir changer de
prestataire sans modifier le registre d'identités, les sessions ou les droits.
La clé d'API est fournie uniquement par l'environnement protégé du service.

Le canal est fermé par défaut. Une configuration incomplète ou un prestataire
indisponible ferme la connexion par courriel sans affecter Infomaniak.

## Données persistées

La table `email_login_tokens` contient : identifiant de demande, empreinte,
identité cible, retour local, état et dates de demande, expiration,
consommation ou invalidation. Elle ne contient ni secret brut, ni adresse de
courriel, ni contenu du message.

Le secret figure nécessairement dans l'URL initiale reçue par l'utilisateur,
mais jamais dans la page de confirmation, le formulaire, MariaDB ou l'audit.
Les journaux du frontal devront exclure la chaîne de requête de cette route.

Les états autorisés sont :

- `issued` : lien émis et non utilisé ;
- `consumed` : lien utilisé une fois ;
- `delivery_failed` : remise échouée, lien définitivement neutralisé.

## Conséquences

Le courriel devient une alternative réellement ouverte : l'utilisateur n'a
pas besoin d'un compte Infomaniak, Google, Microsoft ou GitHub. Cette
universalité ne doit cependant pas être confondue avec une inscription libre :
la création et les droits de l'identité NSK restent gouvernés séparément.

Google, Microsoft, GitHub, le rattachement de plusieurs méthodes et WebAuthn
restent des lots distincts. Ils réutiliseront le sélecteur central et la même
session, sans fusion automatique fondée sur une adresse identique.
