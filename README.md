# Auth Service

## Description
Microservice d'authentification gérant les opérations liées à la connexion, inscription, et gestion des utilisateurs.

## Fonctionnalités
- Authentification email/mot de passe
- OAuth (Google, Facebook)
- Gestion des tokens JWT
- Réinitialisation de mot de passe
- Vérification de token

## Prérequis
- Node.js (v16+)
- MongoDB
- Services dépendants :
  - `data-service`

## Installation

1. Cloner le dépôt
```bash
git clone <url-du-repository>
cd auth-service
```

2. Installer les dépendances
```bash
npm install
```

3. Configurer les variables d'environnement
- Copier `.env.example` en `.env`
- Remplir avec vos configurations

## Démarrage

### Développement
```bash
npm run dev
```

### Production
```bash
npm start
```

## Variables d'Environnement

| Variable | Description | Exemple |
|----------|-------------|---------|
| `PORT` | Port du service | `5001` |
| `JWT_SECRET` | Clé secrète JWT | `supersecretkey` |
| `DATA_SERVICE_URL` | URL du service de données | `http://localhost:5002/api` |
| `GOOGLE_CLIENT_ID` | ID client OAuth Google | `xxx.apps.googleusercontent.com` |

## Architecture

- **Controllers**: Logique métier d'authentification
- **Services**: Communication avec d'autres services
- **Middlewares**: Validation et authentification
- **Config**: Configuration OAuth et JWT

## Sécurité

- Hashage des mots de passe
- Tokens JWT
- Protection contre les attaques CSRF
- Limitation de débit
- Validation des entrées

## Routes Principales

- `POST /auth/register` : Inscription
- `POST /auth/login` : Connexion
- `POST /auth/oauth/google` : Connexion OAuth Google
- `POST /auth/forgot-password` : Mot de passe oublié
- `POST /auth/reset-password` : Réinitialisation de mot de passe

## Tests

```bash
npm test
```

## Déploiement

Utilisez Docker ou votre orchestrateur de conteneurs préféré.

## Contribuer

1. Fork du projet
2. Créer une branche de fonctionnalité
3. Commiter vos modifications
4. Push et ouvrir une Pull Request

## Licence

MIT