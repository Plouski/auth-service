const logger = require('../utils/logger');

const errorHandler = (err, req, res, next) => {
  // Déterminer le code de statut de l'erreur
  const statusCode = err.statusCode || 500;
  
  // Log détaillé de l'erreur
  logger.error('Erreur globale capturée', {
    message: err.message,
    stack: err.stack,
    method: req.method,
    path: req.path
  });

  // Réponse d'erreur adaptée à l'environnement
  const errorResponse = {
    message: err.message || 'Une erreur interne est survenue',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  };

  // Types d'erreurs spécifiques
  if (err.name === 'ValidationError') {
    // Erreurs de validation
    errorResponse.errors = Object.values(err.errors).map(e => e.message);
  }

  if (err.name === 'UnauthorizedError') {
    // Erreurs d'authentification JWT
    errorResponse.message = 'Authentification requise';
  }

  if (err.response) {
    // Erreurs de requêtes externes (axios)
    errorResponse.externalError = {
      status: err.response.status,
      data: err.response.data
    };
  }

  // Envoyer la réponse d'erreur
  res.status(statusCode).json(errorResponse);
};

module.exports = errorHandler;