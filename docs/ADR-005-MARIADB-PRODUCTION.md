# ADR-005 – MariaDB comme stockage opérationnel du service Node

Statut : **Acceptée pour implémentation, non déployée**  
Date : **10 août 2026**

## Contexte

Le service Node doit conserver les identités, applications, affectations et
preuves d'audit sur le Server Cloud Infomaniak. L'adaptateur mémoire valide le
comportement transactionnel, mais ne constitue pas un stockage durable.

## Décision

MariaDB est retenu pour le stockage opérationnel. Le pilote `mysql2` est
verrouillé dans le dépôt. Chaque écriture métier et son événement d'audit sont
réalisés avec la même connexion et la même transaction InnoDB.

Une ligne singleton `audit_chain_head` est verrouillée avant chaque événement.
Elle sérialise les écritures concurrentes et évite deux branches de chaîne ayant
le même prédécesseur. Les événements restent protégés contre mise à jour et
suppression par des déclencheurs en base.

La connexion active TLS avec validation du certificat par défaut. Les
identifiants resteront exclusivement dans les variables secrètes Infomaniak ;
aucune valeur réelle ne sera versionnée.

## Conditions avant déploiement

- créer une base et un compte dédiés à Administration, sans droits globaux ;
- sauvegarder et tester la restauration avant d'importer une donnée réelle ;
- appliquer le schéma sur une base de validation puis vérifier ses contraintes ;
- tester concurrence, rollback, sauvegarde et restauration sur MariaDB réel ;
- documenter le retour arrière vers la version précédente du service ;
- ne raccorder aucune application tant que l'OIDC et le transport HTTPS ne sont
  pas validés.

## Conséquences

- le modèle de production correspond aux capacités natives du Server Cloud ;
- les accès et l'audit partagent une garantie transactionnelle ;
- le pilote et son graphe de dépendances sont reproductibles via le lockfile ;
- le schéma est prêt, mais sa mise en production exige encore une validation
  réelle et les sauvegardes associées.
