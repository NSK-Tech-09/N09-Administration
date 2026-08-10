# ADR-009 – Enregistrement pilote de N09 – Suivi des tâches

Statut : **Acceptée pour la préproduction**
Date : **10 août 2026**

## Enregistrement central

- identifiant immuable : `n09-suivi-taches` ;
- nom : N09 – Suivi des tâches ;
- responsables métier et technique : NSK Tech 09, sous la responsabilité de
  Fred TRAVERS ;
- cycle de vie : actif en préproduction, production non raccordée ;
- inscription : fermée ;
- origine pilote : `https://preprod-taches.nsktech.fr` ;
- service central : `https://preprod-admin.nsktech.fr` ;
- sensibilité : application interne contenant des données de suivi opérationnel ;
- assistance : administration centrale NSK Tech 09.

## Catalogue initial

| Rôle stable | Permissions | Périmètre reconnu |
|---|---|---|
| `tasks-pilot-reader` | `tasks:read` | global pendant le pilote |
| `tasks-reader` | `tasks:read` | site |
| `tasks-writer` | `tasks:read`, `tasks:write` | site |
| `tasks-administrator` | `tasks:read`, `tasks:write`, `tasks:admin` | global |

Seul `tasks-pilot-reader` est amorçable dans ce lot. Les autres rôles décrivent
le contrat cible et ne créent aucune affectation.

## Frontière technique

Suivi des tâches appelle la décision centrale avec une identité technique
distincte de toute session humaine. Chaque requête lie méthode, chemin,
horodatage, nonce et empreinte du corps dans une signature HMAC-SHA-256. La
fenêtre est limitée à trente secondes et un nonce accepté ne peut pas être
rejoué. Le secret reste hors dépôt et peut être renouvelé indépendamment.

La première intégration fonctionne en observation : la décision locale reste
effective, la décision centrale est comparée et un écart est journalisé sans
modifier l'accès. Une indisponibilité centrale n'accorde jamais de droit
nouveau. La bascule ne sera autorisée qu'après parité démontrée.
