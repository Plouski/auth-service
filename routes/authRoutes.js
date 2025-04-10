const express = require('express');
const passport = require('passport');
const AuthController = require('../controllers/authController');
const OAuthController = require('../controllers/oauthController');
const { validationResult } = require('express-validator');
const { authMiddleware } = require('../middlewares/authMiddleware');
const authValidators = require('../middlewares/authValidators');
const validateRequest = require('../middlewares/validateRequest');

const router = express.Router();

// Standard Authentication Routes
//OK
router.post('/register', 
  authValidators.register, 
  validateRequest,
  (req, res, next) => AuthController.register(req, res, next)
);

//OK
router.post('/login', 
  authValidators.login, 
  validateRequest,
  (req, res, next) => AuthController.login(req, res, next)
);

router.post('/refresh-token', 
  authValidators.refreshToken, 
  validateRequest,
  (req, res, next) => AuthController.refreshToken(req, res, next)
);

router.post('/verify-token',
  validateRequest,
  (req, res, next) => AuthController.verifyToken(req, res, next)
);

router.post('/verify-account',
  validateRequest,
  (req, res, next) => AuthController.verifyAccount(req, res, next)
);

router.post('/initiate-password-reset',
  validateRequest,
  (req, res, next) => AuthController.initiatePasswordReset(req, res, next)
);

router.post('/reset-password',
  validateRequest,
  (req, res, next) => AuthController.resetPassword(req, res, next)
);

//OK
router.post('/logout', 
  authMiddleware,
  (req, res, next) => AuthController.logout(req, res, next)
);

//OK
router.get('/profile', 
  authMiddleware, 
  (req, res, next) => AuthController.getProfile(req, res, next)
);

//OK
router.put('/profile', 
  authMiddleware,
  validateRequest,
  (req, res, next) => AuthController.updateProfile(req, res, next)
);

//OK
router.put('/change-password', 
  authMiddleware,
  validateRequest,
  (req, res, next) => AuthController.changePassword(req, res, next)
);

//OK
router.delete('/account', 
  authMiddleware,
  validateRequest,
  (req, res, next) => AuthController.deleteUser(req, res, next)
);

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
    scope: ['email']
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