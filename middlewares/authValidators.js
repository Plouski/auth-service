const { body } = require('express-validator');

// Validateurs pour l'authentification
const authValidators = {
  register: [
    body('email')
      .isEmail()
      .withMessage('Veuillez fournir un email valide')
      .normalizeEmail(),
    
    body('password')
      .isLength({ min: 8 })
      .withMessage('Le mot de passe doit contenir au moins 8 caractères')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('Le mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial'),
    
    body('firstName')
      .trim()
      .isLength({ min: 2 })
      .withMessage('Le prénom doit contenir au moins 2 caractères'),
    
    body('lastName')
      .trim()
      .isLength({ min: 2 })
      .withMessage('Le nom doit contenir au moins 2 caractères')
  ],
  
  login: [
    body('email')
      .isEmail()
      .withMessage('Veuillez fournir un email valide')
      .normalizeEmail(),
    
    body('password')
      .notEmpty()
      .withMessage('Le mot de passe est requis')
  ],
  
  refreshToken: [
    body('refreshToken')
      .notEmpty()
      .withMessage('Le token de rafraîchissement est requis')
  ],
  
  forgotPassword: [
    body('email')
      .isEmail()
      .withMessage('Veuillez fournir un email valide')
      .normalizeEmail()
  ],
  
  resetPassword: [
    body('token')
      .notEmpty()
      .withMessage('Le token est requis'),
    
    body('password')
      .isLength({ min: 8 })
      .withMessage('Le mot de passe doit contenir au moins 8 caractères')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('Le mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial')
  ]
};

module.exports = authValidators;