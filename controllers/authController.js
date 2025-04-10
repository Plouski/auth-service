// controllers/authController.js - Complet
const axios = require('axios');
const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator');
const JwtConfig = require('../config/jwtConfig');
const logger = require('../utils/logger');

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

      // Création de l'utilisateur via le service de données
      const userData = {
        email,
        password,
        firstName,
        lastName
      };

      logger.info('Tentative de création d\'utilisateur', { email });

      // Envoi de la requête au service de données
      let response;
      try {
        response = await axios.post(
          `${process.env.DATA_SERVICE_URL}/users/register`,
          userData
        );
      } catch (dataServiceError) {
        // Gestion spécifique si l'email existe déjà
        if (dataServiceError.response && dataServiceError.response.status === 409) {
          return res.status(409).json({
            message: 'Cet email est déjà utilisé'
          });
        }
        throw dataServiceError;
      }

      const user = response.data.user;

      // Générer les tokens
      const accessToken = JwtConfig.generateAccessToken(user);
      const refreshToken = JwtConfig.generateRefreshToken(user);

      // Journaliser l'inscription
      logger.logAuthEvent('register', { userId: user._id, email });

      // Envoyer des notifications de confirmation de compte
      try {
        await AuthController.sendVerificationNotifications(user);
        logger.info(`Notifications de vérification envoyées pour ${email}`);
      } catch (notificationError) {
        // Ne pas bloquer l'inscription si les notifications échouent
        logger.warn(`Échec d'envoi des notifications pour ${email}`, notificationError);
      }

      // Envoyer un email de bienvenue
      try {
        await AuthController.sendWelcomeEmail(user._id);
        logger.info(`Email de bienvenue envoyé pour ${email}`);
      } catch (welcomeError) {
        // Ne pas bloquer l'inscription si l'email échoue
        logger.warn(`Échec d'envoi de l'email de bienvenue pour ${email}`, welcomeError);
      }

      res.status(201).json({
        message: 'Utilisateur créé avec succès',
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName
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

      // Utiliser directement l'endpoint de login du data-service
      try {
        const response = await axios.post(
          `${process.env.DATA_SERVICE_URL}/users/login`,
          { email, password }
        );

        // Extraire les données de réponse
        const { user, token } = response.data;

        // Générer nos propres tokens JWT
        const accessToken = JwtConfig.generateAccessToken(user);
        const refreshToken = JwtConfig.generateRefreshToken(user);

        logger.logAuthEvent('login', { userId: user._id || user.id, email });

        res.status(200).json({
          message: 'Connexion réussie',
          user: {
            id: user._id || user.id,
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
        if (error.response && error.response.status === 400) {
          return res.status(400).json({ message: error.response.data.message });
        }
        if (error.response && error.response.status === 401) {
          return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
        }
        throw error;
      }
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
   * Méthode pour envoyer des notifications de vérification de compte
   */
  // static async sendVerificationNotifications(user) {
  //   try {
  //     if (!user || !user.email) {
  //       throw new Error('Utilisateur invalide');
  //     }

  //     // Appeler le service de notification
  //     const response = await axios.post(
  //       `${process.env.NOTIFICATION_SERVICE_URL || 'http://localhost:5003'}/notifications/account-verification`,
  //       { email: user.email },
  //       {
  //         headers: {
  //           'Content-Type': 'application/json'
  //         }
  //       }
  //     );

  //     return response.data;
  //   } catch (error) {
  //     logger.error(`Échec d'envoi des notifications de vérification pour ${user.email}`, error);
  //     throw error;
  //   }
  // }

  /**
   * Méthode pour envoyer un email de bienvenue
   */
  // static async sendWelcomeEmail(userId) {
  //   try {
  //     if (!userId) {
  //       throw new Error('ID utilisateur requis');
  //     }

  //     // Appeler le service de notification
  //     const response = await axios.post(
  //       `${process.env.NOTIFICATION_SERVICE_URL || 'http://localhost:5003'}/notifications/welcome`,
  //       { userId },
  //       {
  //         headers: {
  //           'Content-Type': 'application/json',
  //           'x-api-key': process.env.SERVICE_API_KEY
  //         }
  //       }
  //     );

  //     return response.data;
  //   } catch (error) {
  //     logger.error(`Échec d'envoi de l'email de bienvenue pour l'utilisateur ${userId}`, error);
  //     throw error;
  //   }
  // }

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

      try {
        // Appeler le service de données pour vérifier le token
        const response = await axios.post(
          `${process.env.DATA_SERVICE_URL}/users/verify-account`,
          { token },
          {
            headers: {
              'Content-Type': 'application/json'
            }
          }
        );

        res.status(200).json({
          message: 'Compte vérifié avec succès',
          user: response.data.user
        });
      } catch (error) {
        if (error.response && error.response.status === 400) {
          return res.status(400).json({
            message: error.response.data.message || 'Token de vérification invalide'
          });
        }
        throw error;
      }
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

      try {
        // Appeler le service de notification
        await axios.post(
          `${process.env.NOTIFICATION_SERVICE_URL || '5005'}/notifications/password-reset`,
          { email },
          {
            headers: {
              'Content-Type': 'application/json'
            }
          }
        );

        // Par sécurité, ne pas indiquer si l'email existe ou non
        res.status(200).json({
          message: 'Si cet email est associé à un compte, des instructions ont été envoyées.'
        });
      } catch (error) {
        logger.error('Échec de l’envoi de l’e-mail de réinitialisation', error.message);
        // Même si ça échoue, ne pas indiquer que l'email existe
        res.status(200).json({
          message: 'Si cet email est associé à un compte, des instructions ont été envoyées.'
        });

        // Mais logger l'erreur
        logger.error(`Échec d'envoi des instructions de réinitialisation pour ${email}`, error);
      }
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

      try {
        // Appeler le service de données pour réinitialiser le mot de passe
        const response = await axios.post(
          `${process.env.DATA_SERVICE_URL}/users/reset-password`,
          {
            email,
            resetCode,
            newPassword
          },
          {
            headers: {
              'Content-Type': 'application/json'
            }
          }
        );

        res.status(200).json({
          message: 'Mot de passe réinitialisé avec succès'
        });
      } catch (error) {
        if (error.response && error.response.status === 400) {
          return res.status(400).json({
            message: error.response.data.message || 'Code de réinitialisation invalide'
          });
        }
        throw error;
      }
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

      try {
        // Appeler le service de données pour récupérer le profil
        const response = await axios.get(
          `${process.env.DATA_SERVICE_URL}/users/profile`,
          {
            headers: {
              Authorization: `Bearer ${req.headers.authorization?.split(' ')[1]}`
            }
          }
        );

        res.status(200).json({
          user: response.data
        });
      } catch (error) {
        if (error.response && error.response.status === 404) {
          return res.status(404).json({
            message: 'Profil utilisateur non trouvé'
          });
        }
        throw error;
      }
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

      const { firstName, lastName, phoneNumber } = req.body;

      // Valider les entrées
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      // Construire l'objet de mise à jour
      const updateData = {};
      if (firstName !== undefined) updateData.firstName = firstName;
      if (lastName !== undefined) updateData.lastName = lastName;
      if (phoneNumber !== undefined) updateData.phoneNumber = phoneNumber;

      try {
        // Appeler le service de données pour mettre à jour le profil
        const response = await axios.put(
          `${process.env.DATA_SERVICE_URL}/users/profile`,
          updateData,
          {
            headers: {
              Authorization: `Bearer ${req.headers.authorization?.split(' ')[1]}`
            }
          }
        );
        res.status(200).json({
          message: 'Profil mis à jour avec succès',
          user: response.data
        });
      } catch (error) {
        if (error.response && error.response.status === 404) {
          return res.status(404).json({
            message: 'Profil utilisateur non trouvé'
          });
        }
        throw error;
      }
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

      try {
        // Appeler le service de données pour changer le mot de passe
        const response = await axios.put(
          `${process.env.DATA_SERVICE_URL}/users/change-password`,
          {
            currentPassword,
            newPassword
          },
          {
            headers: {
              Authorization: `Bearer ${req.headers.authorization?.split(' ')[1]}`
            }
          }
        );

        logger.info(`Mot de passe changé pour l'utilisateur ${userId}`);

        res.status(200).json({
          message: 'Mot de passe changé avec succès'
        });
      } catch (error) {
        if (error.response) {
          if (error.response.status === 404) {
            return res.status(404).json({
              message: 'Utilisateur non trouvé'
            });
          } else if (error.response.status === 401) {
            return res.status(401).json({
              message: 'Mot de passe actuel incorrect'
            });
          }
        }
        throw error;
      }
    } catch (error) {
      if (error.response?.status === 500 && error.response?.data?.message?.includes('mot de passe')) {
        return res.status(400).json({
          message: error.response.data.message
        });
      }

      logger.error('Erreur lors du changement de mot de passe', error);
      return next(error);
    }
  }

  /**
 * Méthode pour supprimer le compte d'un utilisateur
 */
  static async deleteUser(req, res, next) {
    try {
      // Appeler le service de données pour supprimer le compte
      const response = await axios.delete(
        `${process.env.DATA_SERVICE_URL}/users/account`,
        {
          headers: {
            Authorization: `Bearer ${req.headers.authorization?.split(' ')[1]}`
          }
        }
      );

      return res.status(200).json({
        user: response.data
      });

    } catch (error) {
      if (error.response && error.response.status === 404) {
        return res.status(404).json({
          message: 'Utilisateur non trouvé'
        });
      }

      logger.error('Erreur lors de la suppression du compte', error);
      return next(error);
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

      const user = req.user.user || req.user;
      const accessToken = req.user.accessToken;
      const refreshToken = req.user.refreshToken;
      const userId = user._id || user.id;


      if (!accessToken) {
        // fallback si jamais tu veux le régénérer ici (optionnel)
        accessToken = JwtConfig.generateAccessToken(user);
      }

      logger.logAuthEvent('oauth_login', {
        userId,
        provider: user.oauth?.provider || 'auth'
      });

      // Si c'est une première connexion, envoyer un email de bienvenue
      if (user.isNewUser) {
        try {
          await AuthController.sendWelcomeEmail(userId);
          logger.info(`Email de bienvenue envoyé à ${user.email}`);
        } catch (err) {
          logger.warn(`Échec de l'envoi de l'email de bienvenue à ${user.email}`, err);
        }
      }

      const isApiClient = req.get('Accept') === 'application/json';

      if (isApiClient) {
        // Réponse JSON pour un client SPA/mobile
        return res.status(200).json({
          message: 'Authentification OAuth réussie',
          user: {
            id: userId,
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

      // Option cookie sécurisé (à activer si tu veux)
      /*
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 jours
      });
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/oauth-callback`);
      */

    } catch (error) {
      logger.error('Erreur lors du traitement de l\'authentification OAuth', error);
      return next(error);
    }
  }

}

module.exports = AuthController;