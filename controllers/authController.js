const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator');
const User = require('../models/User');
const JwtConfig = require('../config/jwtConfig');
const logger = require('../utils/logger');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

class AuthController {
  /**
   * Inscription d'un nouvel utilisateur avec notifications
   */
  static async register(req, res, next) {
    try {
      // Validation des entrées
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password, firstName, lastName } = req.body;

      logger.info('Tentative de création d\'utilisateur', { email });

      // Vérifier si l'utilisateur existe déjà
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({
          message: 'Cet email est déjà utilisé'
        });
      }

      // Hachage du mot de passe
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Création du token de vérification
      const verificationToken = crypto.randomBytes(32).toString('hex');

      // Création de l'utilisateur
      const newUser = new User({
        email,
        password: hashedPassword,
        firstName,
        lastName,
        verificationToken,
        isVerified: false,
        createdAt: new Date()
      });

      // Sauvegarde de l'utilisateur dans la base de données
      await newUser.save();

      // Générer les tokens
      const accessToken = JwtConfig.generateAccessToken(newUser);
      const refreshToken = JwtConfig.generateRefreshToken(newUser);

      // Journaliser l'inscription
      logger.logAuthEvent('register', { userId: newUser._id, email });

      // Envoyer des notifications de confirmation de compte
      try {
        await AuthController.sendVerificationEmail(newUser);
        logger.info(`Email de vérification envoyé pour ${email}`);
      } catch (notificationError) {
        // Ne pas bloquer l'inscription si les notifications échouent
        logger.warn(`Échec d'envoi de l'email de vérification pour ${email}`, notificationError);
      }

      // Envoyer un email de bienvenue
      try {
        await AuthController.sendWelcomeEmail(newUser);
        logger.info(`Email de bienvenue envoyé pour ${email}`);
      } catch (welcomeError) {
        // Ne pas bloquer l'inscription si l'email échoue
        logger.warn(`Échec d'envoi de l'email de bienvenue pour ${email}`, welcomeError);
      }

      res.status(201).json({
        message: 'Utilisateur créé avec succès',
        user: {
          id: newUser._id,
          email: newUser.email,
          firstName: newUser.firstName,
          lastName: newUser.lastName
        },
        tokens: {
          accessToken,
          refreshToken
        }
      });
    } catch (error) {
      logger.error('Erreur lors de l\'inscription', error);
      next(error);
    }
  }

  /**
   * Connexion d'un utilisateur
   */
  static async login(req, res, next) {
    try {
      // Validation des entrées
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body;

      logger.info('Tentative de connexion', { email });

      // Rechercher l'utilisateur
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
      }

      // Vérifier le mot de passe
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
      }

      // Générer les tokens
      const accessToken = JwtConfig.generateAccessToken(user);
      const refreshToken = JwtConfig.generateRefreshToken(user);

      // Journaliser la connexion
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
      logger.error('Erreur lors de la connexion', error);
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
   * Méthode pour envoyer un email de vérification
   */
  static async sendVerificationEmail(user) {
    try {
      if (!user || !user.email || !user.verificationToken) {
        throw new Error('Utilisateur ou token de vérification invalide');
      }

      // Créer un transporteur de mail
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD
        }
      });

      // URL de vérification
      const verificationUrl = `${process.env.FRONTEND_URL}/verify-account?token=${user.verificationToken}`;

      // Envoyer l'email
      await transporter.sendMail({
        from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM_ADDRESS}>`,
        to: user.email,
        subject: 'Vérification de votre compte',
        html: `
          <h1>Vérification de votre compte</h1>
          <p>Bonjour ${user.firstName},</p>
          <p>Merci de vous être inscrit. Veuillez cliquer sur le lien ci-dessous pour vérifier votre compte :</p>
          <p><a href="${verificationUrl}">Vérifier mon compte</a></p>
          <p>Ce lien expire dans 24 heures.</p>
        `
      });

      return true;
    } catch (error) {
      logger.error(`Échec d'envoi de l'email de vérification pour ${user.email}`, error);
      throw error;
    }
  }

  /**
   * Méthode pour envoyer un email de bienvenue
   */
  static async sendWelcomeEmail(userOrId) {
    try {
      let user = userOrId;
  
      if (typeof userOrId === 'string') {
        user = await User.findById(userOrId);
      }
  
      if (!user || !user.email) {
        throw new Error('Utilisateur invalide');
      }
  
      // Créer un transporteur de mail
      const transporter = require('nodemailer').createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD
        }
      });
  
      // Envoyer l'email
      await transporter.sendMail({
        from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM_ADDRESS}>`,
        to: user.email,
        subject: 'Bienvenue sur notre plateforme',
        html: `
          <h1>Bienvenue !</h1>
          <p>Bonjour ${user.firstName || ''},</p>
          <p>Merci de vous être inscrit sur notre plateforme. Nous sommes ravis de vous compter parmi nos utilisateurs.</p>
          <p>Pour commencer à utiliser nos services, connectez-vous à votre compte :</p>
          <p><a href="${process.env.FRONTEND_URL}/login">Se connecter</a></p>
          <p>L'équipe</p>
        `
      });
  
      return true;
    } catch (error) {
      logger.error(`Échec d'envoi de l'email de bienvenue pour ${userOrId}`, error);
      throw error;
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
          // Envoyer l'email de réinitialisation
          // Créer un transporteur de mail
          const transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: process.env.SMTP_PORT,
            secure: process.env.SMTP_SECURE === 'true',
            auth: {
              user: process.env.SMTP_USER,
              pass: process.env.SMTP_PASSWORD
            }
          });

          // Envoyer l'email
          await transporter.sendMail({
            from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM_ADDRESS}>`,
            to: user.email,
            subject: 'Réinitialisation de votre mot de passe',
            html: `
              <h1>Réinitialisation de mot de passe</h1>
              <p>Bonjour,</p>
              <p>Vous avez demandé la réinitialisation de votre mot de passe. Voici votre code de réinitialisation :</p>
              <h2>${resetCode}</h2>
              <p>Ce code expire dans 1 heure.</p>
              <p>Si vous n'avez pas demandé cette réinitialisation, ignorez cet email.</p>
            `
          });
        } catch (emailError) {
          logger.error(`Échec d'envoi de l'email de réinitialisation pour ${email}`, emailError);
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
          updatedAt: user.updatedAt
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

      // Valider les entrées
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      // Rechercher l'utilisateur
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          message: 'Profil utilisateur non trouvé'
        });
      }

      // Mettre à jour les champs
      if (firstName !== undefined) user.firstName = firstName;
      if (lastName !== undefined) user.lastName = lastName;
      if (phoneNumber !== undefined) user.phoneNumber = phoneNumber;

      user.updatedAt = new Date();
      await user.save();

      res.status(200).json({
        message: 'Profil mis à jour avec succès',
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          phoneNumber: user.phoneNumber,
          role: user.role,
          isVerified: user.isVerified
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

      const { id, email, firstName, lastName, provider } = req.user;
      let user;
      let isNewUser = false;

      // Rechercher l'utilisateur par email
      user = await User.findOne({ email });

      if (!user) {
        // Créer un nouvel utilisateur
        isNewUser = true;
        user = new User({
          email,
          firstName: firstName || '',
          lastName: lastName || '',
          isVerified: true, // L'email est vérifié par le fournisseur OAuth
          oauth: {
            provider,
            providerId: id
          },
          createdAt: new Date()
        });
        await user.save();
      } else {
        // Mettre à jour les infos OAuth si nécessaire
        if (!user.oauth || user.oauth.provider !== provider) {
          user.oauth = {
            provider,
            providerId: id
          };
          await user.save();
        }
      }

      // Générer les tokens
      const accessToken = JwtConfig.generateAccessToken(user);
      const refreshToken = JwtConfig.generateRefreshToken(user);

      logger.logAuthEvent('oauth_login', {
        userId: user._id,
        provider
      });

      // Si c'est une première connexion, envoyer un email de bienvenue
      if (isNewUser) {
        try {
          await AuthController.sendWelcomeEmail(user);
          logger.info(`Email de bienvenue envoyé à ${email}`);
        } catch (err) {
          logger.warn(`Échec de l'envoi de l'email de bienvenue à ${email}`, err);
        }
      }

      const isApiClient = req.get('Accept') === 'application/json';

      if (isApiClient) {
        // Réponse JSON pour un client SPA/mobile
        return res.status(200).json({
          message: 'Authentification OAuth réussie',
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
      }

      // Redirection avec token (pour client web classique)
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