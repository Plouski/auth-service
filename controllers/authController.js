const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator');
const User = require('../models/User');
const Subscription = require('../models/Subscription');
const JwtConfig = require('../config/jwtConfig');
const logger = require('../utils/logger');
const crypto = require('crypto');
const NotificationService = require("../services/notificationService");

function sanitizeError(err) {
  const sanitized = {
    message: err.message,
    stack: err.stack
  };
  if (err.response?.data) sanitized.response = err.response.data;
  if (err.response?.status) sanitized.status = err.response.status;
  return sanitized;
}

class AuthController {
  /**
   * Inscription d'un nouvel utilisateur avec notifications
   */
  static async register(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password, firstName, lastName } = req.body;

      logger.info('Tentative de création d\'utilisateur', { email });

      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({ message: 'Cet email est déjà utilisé' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      const verificationToken = crypto.randomBytes(32).toString('hex');

      const newUser = new User({
        email,
        password: hashedPassword,
        firstName,
        lastName,
        verificationToken,
        isVerified: false,
        createdAt: new Date()
      });

      await newUser.save();

      const accessToken = JwtConfig.generateAccessToken(newUser);
      const refreshToken = JwtConfig.generateRefreshToken(newUser);

      logger.logAuthEvent('register', { userId: newUser._id, email });

      // Tentative d'envoi de l'email de confirmation (sans bloquer l'inscription)
      Promise.race([
        NotificationService.sendConfirmationEmail(newUser.email, newUser.verificationToken),
        new Promise((_, reject) => setTimeout(() => reject(new Error("⏳ Timeout Mailjet")), 6000))
      ]).then(() => {
        console.log("✅ Email de vérification envoyé");
        logger.info(`✅ Email de vérification envoyé via notification-service pour ${email}`);
      }).catch((notificationError) => {
        logger.warn(`⚠️ Échec de l'envoi de l'email via notification-service`, sanitizeError(notificationError));
      });

      return res.status(201).json({
        message: "Utilisateur créé avec succès. Vérifiez votre boîte mail.",
        user: {
          id: newUser._id,
          email: newUser.email,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
        },
        tokens: {
          accessToken,
          refreshToken,
        },
      });
    } catch (error) {
      logger.error("Erreur complète:", sanitizeError(error));
      next(error);
    }
  }

  /**
   * Connexion d'un utilisateur (avec vérification de l'email)
   */
  static async login(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body;
      logger.info('Tentative de connexion', { email });

      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
      }

      if (!user.isVerified) {
        return res.status(403).json({ message: "Veuillez confirmer votre adresse email avant de vous connecter." });
      }

      const accessToken = JwtConfig.generateAccessToken(user);
      const refreshToken = JwtConfig.generateRefreshToken(user);

      logger.logAuthEvent('login', { userId: user._id, email });

      res.status(200).json({
        message: 'Connexion réussie',
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role
        },
        tokens: {
          accessToken,
          refreshToken
        }
      });
    } catch (error) {
      logger.error('Erreur lors de la connexion', sanitizeError(error));
      next(error);
    }
  }

  /**
   * Rafraîchissement du token
   */
  static async refreshToken(req, res, next) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(400).json({ message: 'Token de rafraîchissement requis' });
      }

      try {
        const accessToken = JwtConfig.refreshToken(refreshToken);

        res.status(200).json({
          accessToken
        });
      } catch (error) {
        return res.status(401).json({ message: 'Token de rafraîchissement invalide ou expiré' });
      }
    } catch (error) {
      logger.error('Erreur lors du rafraîchissement du token', error);
      next(error);
    }
  }

  /**
   * Vérification du token
   */
  static async verifyToken(req, res, next) {
    try {
      const token = req.body.token || req.query.token || req.headers['x-access-token'];

      if (!token) {
        return res.status(400).json({ message: 'Token requis' });
      }

      try {
        const decoded = JwtConfig.verifyToken(token);

        res.status(200).json({
          valid: true,
          user: {
            id: decoded.userId,
            email: decoded.email,
            role: decoded.role
          }
        });
      } catch (error) {
        return res.status(401).json({
          valid: false,
          message: error.message
        });
      }
    } catch (error) {
      logger.error('Erreur lors de la vérification du token', error);
      next(error);
    }
  }

  /**
 * Méthode pour gérer la vérification de compte
 */
  static async verifyAccount(req, res, next) {
    try {
      const { token } = req.body;
      if (!token) {
        return res.status(400).json({
          message: 'Token de vérification requis'
        });
      }
      // Rechercher l'utilisateur par token de vérification
      const user = await User.findOne({ verificationToken: token });
      if (!user) {
        return res.status(400).json({
          message: 'Token de vérification invalide'
        });
      }
      // Vérifier si le token n'est pas expiré (24h après création)
      const tokenCreationTime = user.createdAt || new Date(Date.now() - 25 * 60 * 60 * 1000); // Par défaut 25h pour être sûr
      const expirationTime = new Date(tokenCreationTime.getTime() + 24 * 60 * 60 * 1000);
      if (Date.now() > expirationTime) {
        return res.status(400).json({
          message: 'Token de vérification expiré'
        });
      }
      // Mettre à jour l'utilisateur
      user.isVerified = true;
      user.verificationToken = undefined;
      await user.save();

      // Envoyer l'email de bienvenue
      Promise.race([
        NotificationService.sendWelcomeEmail(user.email, user.firstName || ""),
        new Promise((_, reject) => setTimeout(() => reject(new Error("⏳ Timeout Mailjet")), 6000))
      ]).then(() => {
        logger.info(`✅ Email de bienvenue envoyé via notification-service pour ${user.email}`);
      }).catch((notificationError) => {
        logger.warn(`⚠️ Échec de l'envoi de l'email de bienvenue via notification-service`, sanitizeError(notificationError));
      });

      res.status(200).json({
        message: 'Compte vérifié avec succès',
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName
        }
      });
    } catch (error) {
      logger.error('Erreur lors de la vérification du compte', error);
      next(error);
    }
  }

  /**
   * Méthode pour initier une réinitialisation de mot de passe
   */
  static async initiatePasswordReset(req, res, next) {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({
          message: 'Email requis'
        });
      }

      // Rechercher l'utilisateur
      const user = await User.findOne({ email });

      // Même si l'utilisateur n'existe pas, ne pas révéler cette information
      if (user) {
        // Générer un code de réinitialisation
        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
        const resetCodeExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 heure

        // Mettre à jour l'utilisateur
        user.resetCode = resetCode;
        user.resetCodeExpires = resetCodeExpires;
        await user.save();

        try {
          Promise.race([
            NotificationService.sendPasswordResetEmail(email, resetCode),
            new Promise((_, reject) => setTimeout(() => reject(new Error("⏳ Timeout Mailjet")), 6000))
          ])
          .then(() => {
            logger.info(`✅ Email de réinitialisation envoyé pour ${email}`);
          })
          .catch((notificationError) => {
            logger.warn(`⚠️ Échec de l'envoi de l'email de réinitialisation`, sanitizeError(notificationError));
          });
        } catch (notificationError) {
          logger.warn(`Échec de l'envoi du code de réinitialisation via notification-service pour ${email}`, notificationError);
        }
      }

      // Par sécurité, ne pas indiquer si l'email existe ou non
      res.status(200).json({
        message: 'Si cet email est associé à un compte, des instructions ont été envoyées.'
      });
    } catch (error) {
      logger.error('Erreur lors de l\'initiation de la réinitialisation de mot de passe', error);
      next(error);
    }
  }

  /**
  * Méthode pour initier une réinitialisation de mot de passe par SMS
  */
  static async initiatePasswordResetBySMS(req, res, next) {
    try {
      let { phoneNumber } = req.body;
  
      if (!phoneNumber) {
        return res.status(400).json({
          message: 'Numéro de téléphone requis'
        });
      }
  
      console.log(`🔍 Demande de réinitialisation par SMS pour: ${phoneNumber}`);
      
      console.log(`📱 Numéro formaté: ${phoneNumber}`);
  
      // Rechercher l'utilisateur par numéro de téléphone
      const user = await User.findOne({ phoneNumber });
  
      // Vérification explicite si l'utilisateur existe
      if (!user) {
        console.log(`⚠️ Aucun utilisateur trouvé avec le numéro ${phoneNumber}`);
        
        // Pour la sécurité, on ne révèle pas cette information à l'utilisateur
        return res.status(200).json({
          message: 'Si ce numéro est associé à un compte, un code a été envoyé par SMS.'
        });
      }
  
      console.log(`✅ Utilisateur trouvé: ${user.email} (${user._id})`);
  
      // Générer un code de réinitialisation (code numérique de 6 chiffres)
      const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
      const resetCodeExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 heure
  
      // Mettre à jour l'utilisateur
      user.resetCode = resetCode;
      user.resetCodeExpires = resetCodeExpires;
      await user.save();
      
      console.log(`🔐 Code de réinitialisation généré: ${resetCode} (expire: ${resetCodeExpires})`);
  
      // Tentative d'envoi du SMS - sans utiliser Promise.race pour éviter le timeout prématuré
      try {
        console.log(`📤 Tentative d'envoi SMS au ${phoneNumber}`);
        const smsResult = await NotificationService.sendPasswordResetSMS(phoneNumber, resetCode);
        console.log(`📨 SMS envoyé avec succès:`, smsResult);
      } catch (notificationError) {
        // Log détaillé de l'erreur mais on continue le flux
        console.error(`⚠️ Échec de l'envoi du SMS de réinitialisation:`, {
          error: notificationError.message,
          stack: notificationError.stack && notificationError.stack.split('\n').slice(0, 3).join('\n'),
          phoneNumber,
          userId: user._id
        });
        
        // On pourrait ajouter ici un mécanisme de fallback:
        // - Envoi d'un email si l'utilisateur a un email vérifié
        // - Notification à l'administration pour investigation
        // - etc.
      }
  
      // Par sécurité, ne pas indiquer si le numéro existe ou non
      res.status(200).json({
        message: 'Si ce numéro est associé à un compte, un code a été envoyé par SMS.'
      });
    } catch (error) {
      console.error('Erreur lors de l\'initiation de la réinitialisation de mot de passe par SMS', {
        error: error.message,
        stack: error.stack && error.stack.split('\n').slice(0, 3).join('\n'),
        phoneNumber: req.body.phoneNumber
      });
      next(error);
    }
  }

  /**
   * Méthode pour réinitialiser le mot de passe
   */
  static async resetPassword(req, res, next) {
    try {
      const { email, resetCode, newPassword } = req.body;

      if (!email || !resetCode || !newPassword) {
        return res.status(400).json({
          message: 'Email, code de réinitialisation et nouveau mot de passe requis'
        });
      }

      // Rechercher l'utilisateur
      const user = await User.findOne({
        email,
        resetCode,
        resetCodeExpires: { $gt: Date.now() }
      });

      if (!user) {
        return res.status(400).json({
          message: 'Code de réinitialisation invalide ou expiré'
        });
      }

      // Hachage du nouveau mot de passe
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      // Mettre à jour l'utilisateur
      user.password = hashedPassword;
      user.resetCode = undefined;
      user.resetCodeExpires = undefined;
      await user.save();

      res.status(200).json({
        message: 'Mot de passe réinitialisé avec succès'
      });
    } catch (error) {
      logger.error('Erreur lors de la réinitialisation du mot de passe', error);
      next(error);
    }
  }

  /**
   * Méthode pour gérer la déconnexion
   */
  static async logout(req, res, next) {
    try {
      // Si on utilise des cookies pour le stockage des tokens
      if (req.cookies && req.cookies.refreshToken) {
        res.clearCookie('refreshToken');
      }

      // On pourrait aussi maintenir une liste de tokens révoqués
      // mais ce n'est pas nécessaire pour une implémentation simple

      res.status(200).json({
        message: 'Déconnexion réussie'
      });
    } catch (error) {
      logger.error('Erreur lors de la déconnexion', error);
      next(error);
    }
  }

  /**
   * Méthode pour récupérer le profil de l'utilisateur connecté
   */
  static async getProfile(req, res, next) {
    try {
      const userId = req.user.userId;

      // Rechercher l'utilisateur
      const user = await User.findById(userId).select('-password -resetCode -resetCodeExpires -verificationToken');
      if (!user) {
        return res.status(404).json({
          message: 'Profil utilisateur non trouvé'
        });
      }

      // Récupérer l'abonnement actif
      const subscription = await Subscription.findOne({
        userId,
        status: 'active'
      }).select('plan status startDate endDate');

      res.status(200).json({
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          phoneNumber: user.phoneNumber,
          role: user.role,
          isVerified: user.isVerified,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
          authProvider: user.oauth?.provider || 'local',
          subscription: subscription || null
        }
      });
    } catch (error) {
      logger.error('Erreur lors de la récupération du profil', error);
      next(error);
    }
  }

  /**
   * Méthode pour mettre à jour le profil de l'utilisateur
   */
  static async updateProfile(req, res, next) {
    try {
      const userId = req.user.userId;
      const { firstName, lastName, phoneNumber } = req.body;

      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: 'Profil utilisateur non trouvé' });
      }

      const allowedUpdates = { firstName, lastName, phoneNumber };
      for (const key in allowedUpdates) {
        if (allowedUpdates[key] !== undefined) {
          user[key] = allowedUpdates[key];
        }
      }

      await user.save(); // ✅ updatedAt sera mis à jour automatiquement

      res.status(200).json({
        message: 'Profil mis à jour avec succès',
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          phoneNumber: user.phoneNumber,
          role: user.role,
          isVerified: user.isVerified,
          createdAt: user.createdAt // ← utile si tu veux la réafficher
        }
      });
    } catch (error) {
      logger.error('Erreur lors de la mise à jour du profil', error);
      next(error);
    }
  }

  /**
   * Méthode pour changer le mot de passe
   */
  static async changePassword(req, res, next) {
    try {
      const userId = req.user.userId;
      const { currentPassword, newPassword } = req.body;

      // Valider les entrées
      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          message: 'Le mot de passe actuel et le nouveau mot de passe sont requis'
        });
      }

      // Rechercher l'utilisateur
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          message: 'Utilisateur non trouvé'
        });
      }

      // Vérifier le mot de passe actuel
      const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({
          message: 'Mot de passe actuel incorrect'
        });
      }

      // Vérifier que le nouveau mot de passe est différent
      const isSamePassword = await bcrypt.compare(newPassword, user.password);
      if (isSamePassword) {
        return res.status(400).json({
          message: 'Le nouveau mot de passe doit être différent du mot de passe actuel'
        });
      }

      // Hachage du nouveau mot de passe
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      // Mettre à jour l'utilisateur
      user.password = hashedPassword;
      user.updatedAt = new Date();
      await user.save();

      logger.info(`Mot de passe changé pour l'utilisateur ${userId}`);

      res.status(200).json({
        message: 'Mot de passe changé avec succès'
      });
    } catch (error) {
      logger.error('Erreur lors du changement de mot de passe', error);
      next(error);
    }
  }

  /**
   * Méthode pour supprimer le compte d'un utilisateur
   */
  static async deleteUser(req, res, next) {
    try {
      const userId = req.user.userId;

      // Rechercher et supprimer l'utilisateur
      const user = await User.findByIdAndDelete(userId);
      if (!user) {
        return res.status(404).json({
          message: 'Utilisateur non trouvé'
        });
      }

      logger.info(`Compte supprimé pour l'utilisateur ${userId}`);

      res.status(200).json({
        message: 'Compte supprimé avec succès'
      });
    } catch (error) {
      logger.error('Erreur lors de la suppression du compte', error);
      next(error);
    }
  }

  /**
   * Méthode pour gérer les connexions OAuth
   */
  static async handleOAuthSuccess(req, res, next) {
    try {
      if (!req.user) {
        return res.status(401).json({ message: 'Authentification OAuth échouée' });
      }

      // ✅ Corrigé : extraire les bonnes valeurs
      const { user, accessToken, refreshToken } = req.user;
      const { _id, email, firstName, lastName, role, avatar } = user;

      logger.logAuthEvent('oauth_login', { userId: _id, provider: user.oauth?.provider });

      // Redirection JSON ou vers frontend
      const isApiClient = req.get('Accept') === 'application/json';

      if (isApiClient) {
        return res.status(200).json({
          message: 'Authentification OAuth réussie',
          user: {
            id: _id,
            email,
            firstName,
            lastName,
            role,
            avatar
          },
          tokens: {
            accessToken,
            refreshToken
          }
        });
      }

      const redirectUrl = new URL(process.env.FRONTEND_URL || 'http://localhost:3000');
      redirectUrl.pathname = '/oauth-callback';
      redirectUrl.searchParams.set('token', accessToken);

      return res.redirect(redirectUrl.toString());

    } catch (error) {
      logger.error('Erreur lors du traitement de l\'authentification OAuth', error);
      next(error);
    }
  }
}

module.exports = AuthController;