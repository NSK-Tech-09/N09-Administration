# Lot 41 — Traitement autonome des notifications en préproduction

Statut : **fusionné, déployé et validé en préproduction**

Date de validation : **13 août 2026**

## Release et contrôles

La PR GitHub **#44** a été fusionnée dans `main`. La release immuable active
est `releases/3338ea8`, issue du commit exact
`3338ea8cb48dc27d7518b4002ca55e5198b848e5`.

Les **155 tests Node.js** réussissent sur Infomaniak, sans échec. Le démarrage
du service est conditionné par les marqueurs de tests, sauvegarde, schéma,
cycle manuel, fermeture des canaux externes, intégrité et aptitude au
déploiement.

La release précédente `releases/7813eca` reste disponible pour un retour
arrière immédiat.

## Sauvegarde préalable

L’export logique contrôlé est conservé sous :

`/srv/customer/backups/preprod-admin/lot41-pre-data-20260812T215501Z.sql.gz`

- taille : **17 817 octets** ;
- SHA-256 :
  `881183a41d3fe85b81c645d67dd7cbc73873d1c2cad4e80b41bc071bb35fe2e6` ;
- archive gzip valide ;
- fin d’export MariaDB confirmée.

## Évolution de données

La table additive singleton `notification_processing_state` a été créée par le
compte DDL dédié. Le compte d’exécution de l’application a correctement refusé
la commande `CREATE`, ce qui confirme la séparation des privilèges.

La table conserve seulement l’état borné du dernier cycle. Elle ne contient ni
charge métier, ni adresse, ni titre, ni message, ni identité de machine.

## Gardes actives

La préproduction porte explicitement :

- `N09_ENVIRONMENT=preprod` ;
- `N09_ALLOW_NOTIFICATION_PROCESSING=true` ;
- `N09_ALLOW_EXTERNAL_NOTIFICATION_DELIVERY=false`.

Le cycle manuel initial a réussi avec zéro événement réclamé, traité, repris
ou mis en quarantaine. La chaîne d’audit est valide et le nombre de livraisons
externes non bloquées est nul.

## Ordonnancement réel

Le planificateur natif de l’hébergement Infomaniak ne propose aucun site pour
une application Node.js. Le compte SSH ne fournit par ailleurs ni `crontab` ni
`systemd-run`.

L’ordonnancement standard est donc supervisé par le même groupe de processus
que le serveur HTTP géré par Infomaniak :

- le serveur HTTP et le cycle périodique démarrent et s’arrêtent ensemble ;
- un cycle ponctuel est invoqué toutes les 60 secondes ;
- le verrou nommé MariaDB empêche tout chevauchement entre instances ;
- les baux existants assurent la reprise après interruption ;
- aucun second service, conteneur ou fichier d’état local n’est créé ;
- le retour arrière reste une seule modification de la commande de lancement.

Deux cycles autonomes successifs ont été observés à **03:23** puis **03:24**,
heure de Paris. Tous deux ont réussi avec zéro élément pris, traité, repris ou
mis en quarantaine. Le contrôle final a observé la version de cycle **4**.

## Recette fonctionnelle

La page authentifiée `/admin/notification-operations` confirme :

- dernier cycle réussi ;
- zéro événement à traiter ou en cours ;
- deux événements historiques traités ;
- zéro quarantaine ;
- zéro notification non lue ;
- canaux externes **tous bloqués** ;
- chaîne d’audit valide lors du contrôle serveur final.

La page reste strictement en lecture seule. Elle ne permet ni retraitement, ni
déblocage, ni modification de préférence.

## Conclusion

Le consommateur interne est autonome en préproduction sans ouvrir de canal
externe. La sauvegarde, la release précédente et les preuves d’intégrité sont
conservées. Aucune modification de production n’a été effectuée.

## Références

- `ADR-017-MATERIALISATION-CENTRE-NOTIFICATIONS.md`
- `ADR-018-OBSERVABILITE-NOTIFICATIONS.md`
- `ADR-019-TRAITEMENT-AUTONOME-NOTIFICATIONS.md`
- PR GitHub `NSK-Tech-09/N09-Administration#44`
