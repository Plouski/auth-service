const { validationResult } = require('express-validator');
const logger = require('../utils/logger');

const validateRequest = (req, res, next) => {
  // Extraire les erreurs de validation
  const errors = validationResult(req);

  // S'il y a des erreurs, renvoyer une réponse d'erreur
  if (!errors.isEmpty()) {
    // Logger les erreurs de validation de manière détaillée
    logger.warn('Erreurs de validation des requêtes', {
      errors: errors.array(),
      method: req.method,
      path: req.path,
      body: req.body || {},
      query: req.query || {},
      user: req.user ? req.user.email : 'Non authentifié'
    });

    // Renvoyer une réponse détaillée avec les erreurs
    return res.status(400).json({
      message: 'Erreurs de validation des données',
      errors: errors.array().map(error => ({
        field: error.path,
        message: error.msg
      }))
    });
  }

  // Si pas d'erreurs, passer au middleware suivant
  next();
};

module.exports = validateRequest;