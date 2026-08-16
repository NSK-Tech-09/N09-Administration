# ADR-023 — Livraison par courriel des notifications de Tâches

## Décision

N09 – Administration reste l’unique autorité de livraison. N09 – Suivi des
tâches détermine les destinataires et leurs préférences, mais ne manipule ni
adresse de livraison centrale ni secret Brevo.

Au moment de l’envoi, Administration relit l’identité centrale active. Le
courriel est donc adressé à la valeur courante de `identities.email` — pour
Fred TRAVERS, `f.travers@nsktech.fr` — et non à une copie historique ou à
l’identifiant du fournisseur de connexion.

## Gardes

- aucune livraison externe sans `N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY=true` ;
- aucun événement antérieur à `N09_NOTIFICATION_EXTERNAL_DELIVERY_NOT_BEFORE` ;
- seuls les événements demandant explicitement le canal `email` deviennent
  livrables ; les autres canaux restent bloqués ;
- prise sous bail, idempotence par notification et canal, reprises
  exponentielles bornées puis quarantaine ;
- corps générique et lien vers la tâche, sans reprendre le contenu libre de la
  demande dans le courriel ;
- aucune clé Brevo, adresse de destinataire ou réponse du fournisseur dans
  l’audit.

## Mise en service sans dette historique

1. déployer le code avec les deux gardes à `false` ;
2. activer seulement `N09_ALLOW_NOTIFICATION_PROCESSING` et vider la file
   interne : les livraisons externes historiques sont enregistrées bloquées ;
3. vérifier l’absence de remise en attente et de quarantaine ;
4. fixer `N09_NOTIFICATION_EXTERNAL_DELIVERY_NOT_BEFORE` à l’instant du Go,
   renseigner `N09_TASKS_PUBLIC_ORIGIN`, puis ouvrir la garde externe ;
5. exécuter séparément `process:notifications` et
   `deliver:notification-emails` ;
6. produire une action de recette postérieure au coupe-circuit et confirmer la
   réception sur `f.travers@nsktech.fr` avant d’annoncer le canal opérationnel
dans Tâches.

En hébergement Infomaniak, le planificateur Web ne sait appeler que des URL.
Lorsque `N09_ALLOW_NOTIFICATION_PROCESSING=true`, le processus Node démarre donc
une boucle interne, sans chevauchement, à la cadence bornée par
`N09_NOTIFICATION_WORKER_INTERVAL_MS`. Elle matérialise d'abord les événements,
puis n'appelle la livraison courriel que si sa garde indépendante est ouverte.
Les verrous MariaDB des deux traitements restent l'autorité contre les doubles
exécutions et le cycle s'arrête proprement avec le service.

## Retour arrière

Remettre immédiatement `N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY=false`. Les
notifications internes restent disponibles et aucune livraison nouvelle ne
peut être créée ni réclamée. Les lignes déjà livrées restent conservées comme
preuve ; aucune suppression n’est nécessaire.
