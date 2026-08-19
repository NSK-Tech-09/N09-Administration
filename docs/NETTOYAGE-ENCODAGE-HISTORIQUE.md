# Nettoyage global de l’encodage historique

Le registre courant communique avec MariaDB en `utf8mb4`. Le défaut traité ici vient de textes historiques dont les octets UTF-8 ont autrefois été relus comme Windows-1252.

## Périmètre

Le nettoyage couvre les données humaines modifiables : noms d’identités et d’applications, motifs de rattachement et d’affectation, libellés et motifs de session, demandes d’accès et justifications de décision.

Les identifiants techniques, adresses, URL, catalogues versionnés, notifications immuables et événements d’audit ne sont jamais réécrits.

## Garanties

- prévisualisation sans écriture ;
- transformation déterministe des séquences reconnues, y compris lorsqu’elles sont doubles ou mêlées à du texte français correct ;
- liste blanche fermée des tables et colonnes ;
- transaction unique avec comparaison de la valeur précédente ;
- événement d’audit unique contenant seulement le nombre, les colonnes et l’empreinte du lot ;
- second balayage après application ;
- relance idempotente : le résultat attendu est zéro changement.

La procédure GitHub `Nettoyer l’encodage historique en production` doit d’abord être exécutée en mode `preview`, puis en mode `apply` avec les confirmations exactes demandées.
