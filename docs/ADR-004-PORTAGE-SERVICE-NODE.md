# ADR-004 – Portage contrôlé du service vers Node.js

Statut : **Acceptée**
Date : **10 août 2026**

## Contexte

Le noyau Python et son stockage SQLite ont permis de stabiliser le domaine, les
transactions et l'audit sans dépendance. Le Server Cloud managé retenu pour NSK
Tech 09 exécute durablement Node.js et MariaDB, mais pas un service Python. Une
réécriture immédiate et indépendante créerait deux interprétations des droits.

## Décision

Le service opérationnel sera porté progressivement vers Node.js 24. Le noyau
Python reste l'oracle de comportement pendant la transition. Chaque règle portée
doit reproduire ses codes de décision à partir des mêmes vecteurs de conformité.
Le premier lot couvre la fonction pure de décision et la frontière de l'API
interne, sans transport, stockage ou jeton réel.

Les lots suivants porteront séparément le stockage transactionnel et l'audit,
puis la validation OIDC et le transport HTTPS. Aucun appel de l'écosystème ne
sera ouvert avant égalité des décisions, validation cryptographique et retour
arrière documenté.

## Conséquences

- un seul comportement métier, vérifié dans deux moteurs pendant la migration ;
- aucun service Python artificiellement maintenu sur un hébergement inadapté ;
- aucune décision d'accès fondée sur le démonstrateur d'interface ;
- retrait du noyau Python seulement après parité complète et décision explicite.
