const express = require('express');
const passport = require('passport');
const AuthController = require('../controllers/authController');

const router = express.Router();

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

router.get('/oauth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: '/login', 
    session: false 
  }),
  (req, res, next) => AuthController.handleOAuthSuccess(req, res, next)
);

router.get('/oauth/facebook',
  passport.authenticate('facebook', {
    scope: ['email'],
    auth_type: "rerequest"
  })
);

router.get('/oauth/facebook/callback',
  passport.authenticate('facebook', { 
    failureRedirect: '/login', 
    session: false 
  }),
  (req, res, next) => AuthController.handleOAuthSuccess(req, res, next)
);

router.get('/oauth/github',
  passport.authenticate('github', {
    scope: ['user:email']
  })
);

router.get('/oauth/github/callback',
  passport.authenticate('github', { 
    failureRedirect: '/login', 
    session: false 
  }),
  (req, res, next) => AuthController.handleOAuthSuccess(req, res, next)
);

module.exports = router;