const express = require('express');
const passport = require('passport');
const AuthController = require('../controllers/authController');
const OAuthController = require('../controllers/oauthController');
const authValidators = require('../middlewares/authValidators');
const { authMiddleware } = require('../middlewares/authMiddleware');

const router = express.Router();

// Routes d'authentification standard
router.post('/register', authValidators.register, AuthController.register);
router.post('/login', authValidators.login, AuthController.login);
router.post('/refresh-token', authValidators.refreshToken, AuthController.refreshToken);
router.post('/verify-token', AuthController.verifyToken);

// Route protégée pour tester l'authentification
router.get('/me', authMiddleware, (req, res) => {
  res.status(200).json({
    user: req.user,
    message: 'Authentification valide'
  });
});

// Routes OAuth Google
router.get('/oauth/google', (req, res, next) => {
  console.log('➡️ Route /oauth/google appelée !');
  next();
}, passport.authenticate('google', {
  scope: [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
  ]
}));


router.get('/oauth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login', session: false }),
  OAuthController.oauthCallback
);

// Routes OAuth Facebook
router.get('/oauth/facebook',
  passport.authenticate('facebook', {
    scope: ['email']
  })
);

router.get('/oauth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login', session: false }),
  OAuthController.oauthCallback
);

// Routes OAuth GitHub
router.get('/oauth/github',
  passport.authenticate('github', {
    scope: ['user:email']
  })
);

router.get('/oauth/github/callback',
  passport.authenticate('github', { failureRedirect: '/login', session: false }),
  OAuthController.oauthCallback
);

module.exports = router;