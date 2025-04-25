const express = require('express');
const passport = require('passport');
const { body } = require('express-validator');
const AuthController = require('../controllers/authController');
const { authMiddleware } = require('../middlewares/authMiddleware');

const router = express.Router();

/**
 * @route   POST /auth/register
 * @desc    Enregistrer un nouvel utilisateur
 * @access  Public
 */
router.post(
  '/register',
  [
    body('email').isEmail().withMessage('Adresse email invalide'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Le mot de passe doit contenir au moins 8 caractères')
      .matches(/\d/)
      .withMessage('Le mot de passe doit contenir au moins un chiffre')
      .matches(/[A-Z]/)
      .withMessage('Le mot de passe doit contenir au moins une lettre majuscule'),
    body('firstName').notEmpty().withMessage('Le prénom est requis'),
    body('lastName').notEmpty().withMessage('Le nom est requis')
  ],
  AuthController.register
);

/**
 * @route   POST /auth/login
 * @desc    Connexion d'un utilisateur
 * @access  Public
 */
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Adresse email invalide'),
    body('password').notEmpty().withMessage('Le mot de passe est requis')
  ],
  AuthController.login
);

/**
 * @route   POST /auth/refresh-token
 * @desc    Rafraîchir le token d'accès
 * @access  Public
 */
router.post('/refresh-token', AuthController.refreshToken);

/**
 * @route   POST /auth/verify-token
 * @desc    Vérifier la validité d'un token
 * @access  Public
 */
router.post('/verify-token', AuthController.verifyToken);

/**
 * @route   POST /auth/verify-account
 * @desc    Vérifier un compte avec un token
 * @access  Public
 */
router.post('/verify-account', AuthController.verifyAccount);

router.post('/initiate-password-reset', AuthController.initiatePasswordReset);
router.post('/initiate-password-reset-sms', AuthController.initiatePasswordResetBySMS);

router.post(
  '/reset-password',
  [
    body('email').isEmail().withMessage('Adresse email invalide'),
    body('resetCode').notEmpty().withMessage('Le code de réinitialisation est requis'),
    body('newPassword')
      .isLength({ min: 8 })
      .withMessage('Le mot de passe doit contenir au moins 8 caractères')
      .matches(/\d/)
      .withMessage('Le mot de passe doit contenir au moins un chiffre')
      .matches(/[A-Z]/)
      .withMessage('Le mot de passe doit contenir au moins une lettre majuscule')
  ],
  AuthController.resetPassword
);


/**
 * @route   POST /auth/logout
 * @desc    Déconnexion d'un utilisateur
 * @access  Private
 */
router.post('/logout', authMiddleware, AuthController.logout);

/**
 * @route   GET /auth/profile
 * @desc    Récupérer le profil de l'utilisateur connecté
 * @access  Private
 */
router.get('/profile', authMiddleware, AuthController.getProfile);

/**
 * @route   PUT /auth/profile
 * @desc    Mettre à jour le profil de l'utilisateur
 * @access  Private
 */
router.put(
  '/profile',
  [
    authMiddleware,
    body('firstName').optional().notEmpty().withMessage('Le prénom ne peut pas être vide'),
    body('lastName').optional().notEmpty().withMessage('Le nom ne peut pas être vide'),
    body('phoneNumber').optional().isMobilePhone().withMessage('Numéro de téléphone invalide')
  ],
  AuthController.updateProfile
);

/**
 * @route   PUT /auth/change-password
 * @desc    Changer le mot de passe de l'utilisateur
 * @access  Private
 */
router.put(
  '/change-password',
  [
    authMiddleware,
    body('currentPassword').notEmpty().withMessage('Le mot de passe actuel est requis'),
    body('newPassword')
      .isLength({ min: 8 })
      .withMessage('Le mot de passe doit contenir au moins 8 caractères')
      .matches(/\d/)
      .withMessage('Le mot de passe doit contenir au moins un chiffre')
      .matches(/[A-Z]/)
      .withMessage('Le mot de passe doit contenir au moins une lettre majuscule')
  ],
  AuthController.changePassword
);

/**
 * @route   DELETE /auth/account
 * @desc    Supprimer le compte de l'utilisateur
 * @access  Private
 */
router.delete('/account', authMiddleware, AuthController.deleteUser);

// OAuth Routes
//OK
router.get('/oauth/google', 
  (req, res, next) => {
    console.log('➡️ Google OAuth route called!');
    next();
  }, 
  passport.authenticate('google', {
    scope: [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile'
    ]
  })
);

//OK
router.get('/oauth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: '/login', 
    session: false 
  }),
  (req, res, next) => AuthController.handleOAuthSuccess(req, res, next)
);

//OK
router.get('/oauth/facebook',
  passport.authenticate('facebook', {
    scope: ['email'],
    auth_type: "rerequest"
  })
);

//OK
router.get('/oauth/facebook/callback',
  passport.authenticate('facebook', { 
    failureRedirect: '/login', 
    session: false 
  }),
  (req, res, next) => AuthController.handleOAuthSuccess(req, res, next)
);

//OK
router.get('/oauth/github',
  passport.authenticate('github', {
    scope: ['user:email']
  })
);

//OK
router.get('/oauth/github/callback',
  passport.authenticate('github', { 
    failureRedirect: '/login', 
    session: false 
  }),
  (req, res, next) => AuthController.handleOAuthSuccess(req, res, next)
);

module.exports = router;