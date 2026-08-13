# Lot 44 — Persistance transactionnelle et audit des sessions

Statut : **fusionné dans `main` par la PR #46, non déployé**

Date : **13 août 2026**

## Objet

Ce lot poursuit le socle fusionné par la PR #45. Il rend le registre de
sessions utilisable par les deux implémentations de persistance de N09 –
Administration, sans le relier aux parcours de connexion actifs.

Il a été fusionné par la PR #46, commit `206afd3232aacd1bf229eddb95a507c278cd2fc0`.

## Décision

La création et la révocation d’une session constituent des événements de
sécurité. La mutation du registre et l’ajout dans la chaîne d’audit sont donc
réalisés dans une même transaction.

La dernière activité est mise à jour avec une version attendue, sous verrou
MariaDB. Elle ne produit pas un événement d’audit à chaque lecture : ce bruit
affaiblirait la recherche des événements de sécurité et augmenterait inutilement
la charge. La création, la révocation et, dans un lot ultérieur, l’expiration et
le renouvellement cryptographique restent audités.

## Invariants appliqués

- une nouvelle session est active, non révoquée et en version 1 ;
- son identifiant est un UUID et l’empreinte du secret comporte 64 caractères
  hexadécimaux ;
- l’identité, l’application, l’empreinte, la création, l’échéance absolue,
  l’authentification, la durée d’inactivité et le contexte sont immuables ;
- une activité progresse dans le temps et ne dépasse jamais l’échéance absolue ;
- une révocation ne peut pas modifier silencieusement l’activité ;
- toute concurrence sur une version devenue ancienne échoue sans écrasement ;
- l’auteur de l’audit de révocation correspond à l’auteur enregistré dans la
  session ;
- l’audit est refusé s’il contient l’identifiant complet ou l’empreinte du
  secret, même sous un nom de champ détourné.

Le secret brut reste absent du dépôt central, de MariaDB et de l’audit. Son
empreinte n’est disponible que dans le registre interne et n’est jamais reprise
dans la preuve d’audit.

## Persistance mémoire

Le dépôt transactionnel en mémoire couvre désormais :

- création atomique avec audit ;
- unicité de l’identifiant et de l’empreinte ;
- lecture interne et liste triée par identité ;
- actualisation optimiste de l’activité sans audit de lecture ;
- révocation atomique avec audit ;
- annulation complète si un invariant ou l’audit est invalide.

Il conserve ainsi le même contrat que MariaDB pour les tests du noyau.

## Persistance MariaDB

La création utilise la table additive `application_sessions` et ajoute l’audit
avant de valider la transaction.

L’actualisation :

1. verrouille la ligne avec `FOR UPDATE` ;
2. contrôle la version et tous les champs immuables ;
3. contrôle la progression des échéances et l’absence de révocation ;
4. applique la mutation seulement si la ligne est toujours active ;
5. annule la transaction si aucune ligne exacte n’est modifiée.

La révocation suit le même verrouillage, exige la version suivante, conserve
l’activité et ajoute l’événement dans la chaîne d’audit avant validation.

## Validation locale

La suite complète de N09 – Administration réussit avec **172 tests** et aucun
échec. La recette couvre notamment :

- création et audit dans une transaction unique ;
- retour arrière si l’audit échoue ;
- refus d’un état initial non conforme ;
- refus d’un audit qui révèle la référence ou l’empreinte ;
- refus d’un auteur de révocation incohérent ;
- concurrence optimiste et absence d’écrasement ;
- refus d’une activité rétrograde, expirée ou greffée sur une autre session ;
- révocation MariaDB sous verrou avec audit atomique ;
- absence d’audit supplémentaire lors d’une simple activité.

## Frontière volontaire

Ce lot ne crée aucune session réelle et ne modifie pas les cookies actuels. Il
ne branche encore ni le retour OIDC d’Administration, ni le courtage de Suivi
des tâches, ni les décisions d’accès, ni la déconnexion.

L’expiration reste calculée et refusée par le noyau, mais son événement durable
sera ajouté avec le futur traitement de nettoyage afin qu’une session jamais
réutilisée après son échéance soit également tracée. L’interface personnelle et
la révocation distante relèvent de lots ultérieurs.

## Absence d’impact externe

- aucune migration n’a été appliquée à la préproduction ;
- aucune donnée n’a été écrite dans `application_sessions` ;
- aucune release n’a été créée ou redémarrée ;
- aucun cookie, droit, identité ou affectation n’a été modifié ;
- la production demeure inchangée.

## Étape suivante

Introduire un mode d’observation explicitement inopposable : les nouvelles
connexions pourront enregistrer une session centrale et comparer son état, mais
les cookies actuels continueront seuls à décider de l’accès. Cette étape devra
mesurer les créations, activités, échéances et divergences avant toute
activation contraignante.

## Références

- `ADR-020-SESSIONS-APPLICATIVES-REVOCABLES.md`
- `LOT-43-SOCLE-REGISTRE-SESSIONS.md`
- `ARC-010`
- `ARC-013`
- `TST-001`
