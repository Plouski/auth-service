const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GitHubStrategy = require("passport-github").Strategy;
const axios = require('axios');
const logger = require('../utils/logger');

class PassportConfig {
  static initializeStrategies() {
    // Google Strategy
    passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      passReqToCallback: true
    }, async (req, accessToken, refreshToken, profile, done) => {
      try {
        const user = await PassportConfig.handleOAuth('google', profile);
        return done(null, user);
      } catch (err) {
        return PassportConfig.handleOAuthError('google', err, done);
      }
    }));

    // Facebook Strategy
    passport.use(new FacebookStrategy({
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL,
      profileFields: ['id', 'emails', 'name'],
      passReqToCallback: true
    }, async (req, accessToken, refreshToken, profile, done) => {
      try {
        const user = await PassportConfig.handleOAuth('facebook', profile);
        return done(null, user);
      } catch (err) {
        return PassportConfig.handleOAuthError('facebook', err, done);
      }
    }));

    // GitHub Strategy
    passport.use(new GitHubStrategy({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL,
      scope: ["user", "user:email"],
      passReqToCallback: true
    }, async (req, accessToken, refreshToken, profile, done) => {
      try {
        const user = await PassportConfig.handleOAuth('github', profile);
        return done(null, user);
      } catch (err) {
        return PassportConfig.handleOAuthError('github', err, done);
      }
    }));

    // (Dé)sérialisation
    passport.serializeUser((user, done) => {
      done(null, user._id);
    });

    passport.deserializeUser(async (id, done) => {
      try {
        const response = await axios.get(`${process.env.DATA_SERVICE_URL}/users/${id}`);
        done(null, response.data);
      } catch (error) {
        done(error);
      }
    });
  }

  // Fonction générique pour traiter l'OAuth
  static async handleOAuth(provider, profile) {
    try {
      let email = '';
      if (Array.isArray(profile.emails) && profile.emails.length > 0) {
        email = profile.emails.find(e => e.verified)?.value || profile.emails[0].value;
      } else {
        email = `${profile.id}@${provider}.oauth`;
      }

      const firstName = profile.name?.givenName || profile.displayName || '';
      const lastName = profile.name?.familyName || '';

      const providerIdKey = `${provider}Id`;
      const data = {
        email,
        firstName,
        lastName,
        [providerIdKey]: profile.id
      };

      const url = `${process.env.DATA_SERVICE_URL}/oauth/${provider}`;
      console.log(`[OAuth] Appel à ${url} avec:`, data);

      const response = await axios.post(url, data);
      console.log(`[OAuth] Réponse ${provider}:`, response.data);

      return {
        ...response.data,
        user: {
          id: response.data.id,
          email: response.data.email,
          firstName: response.data.firstName,
          lastName: response.data.lastName,
          role: response.data.role,
          isNewUser: response.data.isNewUser
        },
        accessToken: response.data.accessToken,
        refreshToken: response.data.refreshToken
      };
    } catch (error) {
      throw error;
    }
  }

  // Gestion des erreurs centralisée
  static handleOAuthError(provider, error, done) {
    if (error.response) {
      console.error(`❌ Erreur OAuth ${provider} – ${error.response.status}:`, error.response.data);
    } else {
      console.error(`❌ Erreur OAuth ${provider}:`, error.message);
    }
    return done(error, false);
  }
}

module.exports = PassportConfig;
