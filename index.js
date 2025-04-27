require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const passport = require('passport');

const logger = require('./utils/logger');
const PassportConfig = require('./config/passportConfig');
const authRoutes = require('./routes/authRoutes');
const metricsRoutes = require('./routes/metricsRoutes');
const { httpRequestsTotal, httpDurationHistogram } = require('./services/metricsServices');

const app = express();
const PORT = process.env.PORT || 5001;

console.log('🔥 Lancement du serveur...');

(async () => {
  try {
    // ───────────── Connexion MongoDB ─────────────
    await mongoose.connect(process.env.MONGODB_URI);
    logger.info('✅ Connexion MongoDB établie');

    // ───────────── Middlewares globaux ─────────────
    app.use(helmet());
    app.use(cors({
      origin: process.env.CORS_ORIGIN || '*',
      credentials: true,
    }));

    app.use(express.json({ limit: '1mb' }));
    app.use(express.urlencoded({ extended: true }));

    app.use(session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
    }));

    // ───────────── Middleware Prometheus ─────────────
    app.use((req, res, next) => {
      const start = process.hrtime();
      res.on('finish', () => {
        const duration = process.hrtime(start);
        const seconds = duration[0] + duration[1] / 1e9;

        httpRequestsTotal.inc({
          method: req.method,
          route: req.path,
          status_code: res.statusCode,
        });

        httpDurationHistogram.observe({
          method: req.method,
          route: req.path,
          status_code: res.statusCode,
        }, seconds);
      });
      next();
    });

    // ───────────── Passport config ─────────────
    app.use(passport.initialize());
    app.use(passport.session());
    PassportConfig.initializeStrategies();

    // ───────────── Routes principales ─────────────
    app.use('/auth', authRoutes);
    app.use('/metrics', metricsRoutes);

    app.get('/ping', (req, res) => res.status(200).json({ status: 'pong ✅' }));

    // ───────────── Gestion 404 ─────────────
    app.use((req, res) => {
      res.status(404).json({ message: 'Route non trouvée' });
    });

    // ───────────── Gestion erreurs globales ─────────────
    app.use((err, req, res, next) => {
      logger.logApiError(req, err);
      const statusCode = err.statusCode || 500;
      const message = process.env.NODE_ENV === 'production' && statusCode === 500
        ? 'Erreur serveur'
        : err.message;
      res.status(statusCode).json({ status: 'error', message });
    });

    // ───────────── Démarrage du serveur ─────────────
    app.listen(PORT, () => {
      logger.info(`🚀 Serveur en écoute sur http://localhost:${PORT}`);
    });

    // ───────────── Gestion erreurs Node.js ─────────────
    process.on('unhandledRejection', (reason) => {
      logger.error('💥 Unhandled Rejection:', reason);
      process.exit(1);
    });

    process.on('uncaughtException', (error) => {
      logger.error('💥 Uncaught Exception:', error);
      process.exit(1);
    });

  } catch (err) {
    console.error('❌ Erreur fatale au démarrage :', err.message);
    process.exit(1);
  }
})();
