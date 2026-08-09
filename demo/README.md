# Démonstrateur N09 – Administration

Interface locale et entièrement fictive destinée à valider l'expérience de
gestion des identités avant tout raccordement à un fournisseur réel.

Le démonstrateur permet de :

> Les profils affichés sont entièrement fictifs. Le dépôt ne contient ni base
> d'identités réelle, ni secret, ni donnée personnelle issue d'un fournisseur.

- simuler une connexion Infomaniak, Google, Microsoft ou GitHub ;
- rattacher plusieurs portes d'entrée à une identité NSK stable ;
- constater qu'un nouvel utilisateur ne reçoit aucun droit automatiquement ;
- déposer une demande d'accès sans adresse électronique obligatoire ;
- suspendre un compte NSK et bloquer tous ses moyens de connexion ;
- distinguer les niveaux de confiance, notamment pour le téléphone ;
- observer les décisions dans un journal d'audit fictif.

## Utilisation locale

Prérequis : Node.js 22 ou supérieur et pnpm.

```bash
pnpm install
pnpm dev
```

Puis ouvrir `http://localhost:3000/`.

## Limites volontaires

Il ne contient aucune donnée réelle, aucun secret, aucune validation de jeton
et aucun appel à Infomaniak, Google, Microsoft ou GitHub. La connexion réelle
sera ajoutée seulement après validation du parcours.
