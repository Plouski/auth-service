const axios = require('axios');
const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator');
const JwtConfig = require('../config/jwtConfig');
const logger = require('../utils/logger');

class AuthController {
  /**
   * Inscription d'un nouvel utilisateur
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
      
      const response = await axios.post(
        `${process.env.DATA_SERVICE_URL}/register`,
        userData
      );

      const user = response.data;

      // Générer les tokens
      const accessToken = JwtConfig.generateAccessToken(user);
      const refreshToken = JwtConfig.generateRefreshToken(user);

      logger.logAuthEvent('register', { userId: user._id, email });

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
      // Gestion spécifique si l'email existe déjà
      if (error.response && error.response.status === 409) {
        return res.status(409).json({ 
          message: 'Cet email est déjà utilisé'
        });
      }
      
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
          `${process.env.DATA_SERVICE_URL}/login`,
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
        if (error.response && error.response.status === 401) {
          return res.status(401).json({ 
            message: 'Email ou mot de passe incorrect' 
          });
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
}

module.exports = AuthController;