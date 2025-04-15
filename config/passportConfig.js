const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GitHubStrategy = require("passport-github").Strategy;
const logger = require('../utils/logger');
const User = require('../models/User');
const JwtConfig = require('../config/jwtConfig');

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
      enableProof: true
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
        const user = await User.findById(id).select('-password');
        done(null, user);
      } catch (error) {
        done(error);
      }
    });
  }

  static async handleOAuth(provider, profile) {
    let email = null;
  
    if (provider === 'github') {
      const res = await fetch('https://api.github.com/user/emails', {
        headers: {
          Authorization: `token ${profile.accessToken}`,
          'User-Agent': 'OAuth App'
        }
      });
  
      const emails = await res.json();
      if (Array.isArray(emails)) {
        const primary = emails.find(e => e.primary && e.verified);
        const any = emails.find(e => e.verified);
        email = primary?.email || any?.email;
      }
    } else {
      email = Array.isArray(profile.emails) && profile.emails.length > 0
        ? (profile.emails.find(e => e.verified)?.value || profile.emails[0].value)
        : null;
    }
  
    if (!email) {
      email = `oauth_${provider}_${profile.id}@fake.email`;
      logger.warn(`⚠️ Email manquant dans le profil ${provider}, email généré: ${email}`);
    }
  
    const displayName = profile.displayName || '';
    const [firstSplit, ...restSplit] = displayName.trim().split(' ');
  
    const rawFirstName = profile.name?.givenName || firstSplit || null;
    const rawLastName = profile.name?.familyName || restSplit.join(' ') || null;
  
    const clean = str => (typeof str === 'string' && str.trim() !== '' ? str.trim() : null);
  
    const firstName = clean(rawFirstName) || 'Utilisateur';
    const lastName = clean(rawLastName) || 'OAuth';
  
    if (!rawFirstName || !rawLastName) {
      logger.warn(`⚠️ Prénom ou nom manquant dans le profil ${provider} (${email}), fallback utilisé : ${firstName} ${lastName}`);
    }
  
    let user = await User.findOne({ email });
    let isNewUser = false;
  
    if (!user) {
      isNewUser = true;
      try {
        user = new User({
          email,
          firstName,
          lastName,
          isVerified: true,
          oauth: {
            provider,
            providerId: profile.id
          },
          createdAt: new Date()
        });
        await user.save();
      } catch (err) {
        if (err.code === 11000) {
          user = await User.findOne({ email });
          isNewUser = false;
        } else {
          throw err;
        }
      }
    } else if (!user.oauth || user.oauth.providerId !== profile.id) {
      user.oauth = {
        provider,
        providerId: profile.id
      };
      await user.save();
    }
  
    const accessToken = JwtConfig.generateAccessToken(user);
    const refreshToken = JwtConfig.generateRefreshToken(user);
  
    return {
      user: {
        ...user.toJSON(),
        isNewUser
      },
      accessToken,
      refreshToken
    };
  }
  
  

  static handleOAuthError(provider, error, done) {
    logger.error(`❌ Erreur OAuth ${provider}:`, error);
    return done(error, false);
  }
}

module.exports = PassportConfig;
