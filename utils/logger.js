const winston = require('winston');
const path = require('path');

// Créer un logger personnalisé qui garantit les méthodes de log
class CustomLogger {
  constructor() {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.splat(),
        winston.format.json()
      ),
      defaultMeta: { service: 'auth-service' },
      transports: [
        // Console pour development
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        }),
        
        // Fichier pour les logs d'erreur
        new winston.transports.File({
          filename: path.join(__dirname, '../logs/error.log'),
          level: 'error',
          maxsize: 5242880, // 5MB
          maxFiles: 5
        }),
        
        // Fichier pour tous les logs
        new winston.transports.File({
          filename: path.join(__dirname, '../logs/combined.log'),
          maxsize: 5242880, // 5MB
          maxFiles: 5
        })
      ]
    });

    // Si on est en production, ne loguer que dans les fichiers
    if (process.env.NODE_ENV === 'production') {
      this.logger.remove(this.logger.transports.find(t => t.name === 'console'));
    }
  }

  // Méthodes de log sécurisées
  info(message, meta) {
    return this.logger.info(message, meta);
  }

  error(message, meta) {
    return this.logger.error(message, meta);
  }

  warn(message, meta) {
    return this.logger.warn(message, meta);
  }

  debug(message, meta) {
    return this.logger.debug(message, meta);
  }

  // Méthodes d'extension pour des logs plus spécifiques
  logRequest(req) {
    this.info('Request Received', {
      method: req.method,
      path: req.path,
      body: req.body ? JSON.stringify(req.body) : 'No body',
      query: req.query ? JSON.stringify(req.query) : 'No query',
      user: req.user ? req.user.email : 'Non authentifié'
    });
  }

  logAuthEvent(event, details) {
    this.info(`Auth Event: ${event}`, details);
  }
}

// Exporter une instance unique
module.exports = new CustomLogger();