# Lot 60 — Session centrale N09 – Énergie en production

Date de recette : 14 août 2026, fuseau Europe/Paris.

## Résultat

N09 – Énergie utilise désormais N09 – Administration comme autorité centrale
pour la connexion, l'autorisation et la révocation de session. Le compte humain
reste identifié par son `identity_id` central ; aucun rapprochement par adresse
électronique n'est effectué par l'application.

La production est répartie ainsi :

| Service | Hébergement Cloud | Release |
|---|---:|---|
| N09 – Administration | `818413` | `26b8bf3a8b06e613a7089a77534e9b5bb59146d9` |
| N09 – Énergie | `818553` | `9fbf979ae06adf6623e29a828c9e4daa98afa16e` |
| N09 – Suivi des tâches | `817080` | `3491cff901794c8a3c88c7b9a0537d60b55004e2` |

## Chaîne de confiance validée

1. Énergie crée une demande Authorization Code avec PKCE S256.
2. Administration authentifie la personne via Infomaniak.
3. Administration vérifie l'affectation `energy-owner` et le droit
   `energy:read` avant d'émettre le code à usage unique.
4. Énergie échange le code par un appel serveur à serveur signé.
5. Administration délivre une preuve de session propre à `n09-energie`.
6. Énergie conserve cette preuve dans son cookie chiffré, limité à son domaine.
7. Chaque lecture ou écriture demande une décision centrale avec la preuve de
   session ; une panne ou une révocation ferme l'accès.
8. La déconnexion révoque d'abord la session centrale, puis efface le cookie
   local.

## Données centrales créées

- application `n09-energie`, active, inscription fermée ;
- retour exact `https://energie.nsktech.fr/auth/nsk/callback` ;
- politique de connexion exigeant `energy:read` ;
- affectation propriétaire globale avec `energy:read` et `energy:write` ;
- catalogue d'accès version 1, empreinte
  `f5f3f66c947555a0ff5d806d8d9501959427821db334c1ee378fb9ea4948cc59`.

L'amorçage a vérifié la chaîne d'audit. Sa seconde exécution n'a créé aucun
objet supplémentaire.

## Recette réelle

- 268 tests Administration réussis localement et sur la release Cloud ;
- 75 tests Énergie réussis sur la release Cloud ;
- 214 tests serveur et 34 tests frontend Tâches réussis sur la release Cloud ;
- connexion réelle Énergie avec le compte `Fred TRAVERS` ;
- affichage des mesures en direct et autorisation de lecture validés ;
- déconnexion centrale confirmée, suivie d'une nouvelle connexion réussie ;
- connexion réelle Tâches avec `Frédéric TRAVERS` et droits recalculés par site ;
- réponses publiques HTTPS `200`, HSTS, anti-cadrage, anti-détection MIME,
  politique de référent et politique de permissions vérifiés ;
- CSP stricte vérifiée sur Suivi des tâches.

## Retour arrière

- Administration : repointer `current` vers la release précédente
  `3811ca42fe70d9a63043ca18397124effbdf27ce`, puis redémarrer ;
- Énergie : restaurer l'archive protégée
  `backups/n09-energie/pre-central-9fbf979.tar.gz`, puis redémarrer ;
- Tâches : repointer `current` vers la release précédente
  `961cc09768e6b644b5713e0ac6c14543a41ee8e1`, puis redémarrer.

Les comptes SSH temporaires utilisés pour le déploiement ont été supprimés
après la recette. Aucun secret n'est consigné dans ce document.

## Dette restante hors lot

La résiliation de l'ancien hébergement `814587` reste interdite tant que :

- le portail `nsktech.fr` n'est pas détaché de son autorité temporaire et
  déployé sur le Cloud ;
- `admin.nsktech.fr` et `taches.nsktech.fr` ne sont pas rattachés aux services
  Cloud avec certificats valides ;
- l'archive historique Énergie n'est pas copiée et restaurée hors de cet
  hébergement ;
- l'inventaire final DNS, base, fichiers et trafic n'est pas vide.
