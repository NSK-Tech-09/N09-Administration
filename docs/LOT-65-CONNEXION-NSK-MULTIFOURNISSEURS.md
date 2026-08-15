# Lot 65 — Connexion NSK multifournisseurs

## Décision

NSK Tech 09 reste propriétaire de l'identité interne et des droits. Un
fournisseur de connexion apporte seulement une preuve d'identité externe. Il
ne devient ni le compte NSK, ni une source d'autorisation.

La connexion commence donc sur une page aux couleurs de NSK Tech 09. Cette
page explique le rôle du fournisseur et présente uniquement comme utilisables
les méthodes réellement configurées. Infomaniak est le premier fournisseur
actif ; il n'est plus imposé par une redirection invisible.

## Invariants de sécurité

- l'identité NSK conserve un identifiant technique immuable ;
- un lien externe est identifié par le couple `issuer` + `subject`, jamais par
  la seule adresse électronique ;
- le rattachement d'une nouvelle méthode à une identité existante exige une
  session NSK active et une nouvelle preuve du fournisseur ;
- aucun fournisseur, domaine de courriel ou numéro de téléphone ne crée de
  droit applicatif ;
- aucun mot de passe de fournisseur n'est collecté ni stocké par NSK Tech 09 ;
- tout rattachement, retrait ou échec sensible est audité ;
- le retour applicatif et le thème sont limités aux valeurs autorisées.

## État du lot

La page `/portal/login` présente désormais la connexion NSK avant tout départ
vers un fournisseur. Elle conserve la destination d'origine et le thème. Le
bouton Infomaniak reste opérationnel avec le parcours Authorization Code et
PKCE existant. Google, Microsoft, GitHub et la connexion par courriel sont
annoncés comme prévus mais ne sont pas activables tant que leur configuration
et leur recette de sécurité ne sont pas terminées.

## Trajectoire d'ouverture

1. **Courriel sans mot de passe** : offrir en priorité l'alternative la plus
   universelle avec un lien à usage unique, à durée de vie courte, stocké sous
   forme de condensat, limité en fréquence et invalidé après consommation. Le
   message ne doit révéler l'existence d'aucun compte.
2. **Google, Microsoft et GitHub** : enregistrer une application OAuth/OIDC
   pour chaque fournisseur, isoler les secrets par environnement, vérifier
   signature, `state`, `nonce`, PKCE, émetteur, audience et URL de retour.
3. **Rattachement multifournisseur** : permettre depuis « Mon compte »
   d'ajouter ou retirer une méthode après réauthentification, sans rapprochement
   automatique fondé sur un courriel identique.
4. **Téléphone** : le réserver d'abord à la récupération ou au second facteur.
   Son ouverture comme connexion principale dépendra du coût, de la protection
   contre les abus et des risques de réattribution de numéro.
5. **Clés d'accès WebAuthn** : privilégier à terme cette voie indépendante des
   fournisseurs pour une connexion simple, résistante à l'hameçonnage et sans
   mot de passe.

## Recette exigée avant activation d'un fournisseur

- connexion, refus, annulation et indisponibilité du fournisseur ;
- conservation de la destination et du thème ;
- identité inconnue sans droit implicite ;
- rattachement explicite à une identité existante ;
- absence de fusion par adresse électronique ;
- révocation et reconnexion ;
- journaux sans jeton, secret ni donnée sensible ;
- accessibilité clavier, mobile et thèmes du référentiel NSES.

La production reste inchangée tant que le lot n'est pas publié puis déployé par
une opération explicitement autorisée.
