# ADR-018 — Observabilité gouvernée des notifications

Statut : **implémenté et validé localement, non déployé**

Date : **12 août 2026**

## Contexte

Le lot 39 a démontré la réception, la résolution et la matérialisation durable
des notifications en préproduction. Les deux événements historiques ont été
traités sans notification interne, car aucun destinataire n’était éligible.

Ce résultat est correct, mais son explication exigeait encore un accès direct à
MariaDB. Une telle dépendance à phpMyAdmin constitue une dette d’exploitation :
elle expose un outil trop puissant pour un besoin de lecture et ne permet pas de
gouverner séparément le droit de diagnostic.

## Décision

N09 – Administration expose une console en lecture seule sur
`/admin/notification-operations`. Elle présente uniquement :

- les volumes d’événements par état (`pending`, `processing`, `retry`,
  `processed`, `quarantined`) ;
- les nombres de notifications internes, non lues et archivées ;
- l’état agrégé des livraisons externes et le nombre qui ne serait plus bloqué ;
- les suppressions cumulées par action propre, préférence et identité non liée ;
- les résolutions récentes avec leur application source, leur politique, leur
  référence technique et leurs compteurs.

La console ne montre ni adresse, ni coordonnée de canal, ni titre ou message de
notification, ni charge métier, ni identifiant de personne. Elle ne contient
aucun formulaire de traitement, de relance, de préférence ou d’ouverture de
canal.

## Pouvoir dédié

La lecture exige la permission
`administration:notifications:read`, portée par le rôle central
`notification-operations-reader`. Les pouvoirs de rattachement, de consultation
des accès et de décision d’accès ne remplacent pas cette permission.

Le catalogue Administration passe en version 3. La publication contrôlée
conserve la transition version 1 → version 2 → version 3 afin de respecter
l’immuabilité et la séquence des catalogues. L’affectation initiale du lecteur
d’exploitation dispose d’une commande d’amorçage distincte, bornée à une base
`_preprod`, explicitement activée, justifiée et auditée.

## Persistance et confidentialité

La vue est calculée au moment de la consultation par des agrégats SQL. Elle ne
crée aucune nouvelle table et ne modifie aucun état. La requête de détail récente
ne sélectionne jamais les colonnes `title`, `message`, `payload_json`, les
coordonnées d’identité ou les coordonnées de canal.

L’interface reste servie avec `Cache-Control: no-store`, la politique CSP fermée
et les protections déjà appliquées aux autres consoles centrales.

## Frontière d’exploitation

Ce lot n’active pas le consommateur permanent. La garde
`N09_ALLOW_NOTIFICATION_PROCESSING` reste fermée et tous les canaux externes
restent `blocked`. La console rend précisément ces invariants visibles avant
toute décision ultérieure d’ordonnancement ou d’ouverture de canal.

## Validation locale

- **147 tests Node.js Administration** réussissent ;
- refus d’une session absente ou d’un pouvoir voisin ;
- vérification de l’agrégation MariaDB et de la limite des résolutions récentes ;
- absence de contenu métier, d’adresse et de secret dans les requêtes et la page ;
- absence d’action de traitement dans la console ;
- amorçage préproduction idempotent et chaîne d’audit valide.

## Déploiement prévu

Le déploiement en préproduction devra respecter cet ordre :

1. publier et déployer le code validé ;
2. publier le catalogue Administration v3 avec la commande contrôlée existante ;
3. amorcer le rôle `notification-operations-reader` pour l’identité explicitement
   autorisée ;
4. redémarrer le service et vérifier la santé ;
5. recetter l’accès refusé sans permission puis l’accès autorisé ;
6. vérifier que le nombre de livraisons externes non bloquées reste nul.

La production historique n’est pas modifiée par ce lot local.

## Références

- `ADR-017-MATERIALISATION-CENTRE-NOTIFICATIONS.md`
- `docs/LOT-39-NOTIFICATIONS-PREPROD.md`
- `ARC-015`
- `ERG-018`
- `ARC-013`
- `TST-001`
