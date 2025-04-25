const axios = require("axios");

const NOTIFICATION_SERVICE_URL = process.env.NOTIFICATION_SERVICE_URL || "http://notification-service:3005";
const FREE_MOBILE_USERNAME = process.env.FREE_MOBILE_USERNAME;
const FREE_MOBILE_API_KEY = process.env.FREE_MOBILE_API_KEY;

const NotificationService = {
  sendConfirmationEmail: async (email, token) => {
    try {
      const res = await axios.post(`${NOTIFICATION_SERVICE_URL}/notifications/email`, {
        type: "confirm",
        email,
        tokenOrCode: token
      });
      console.log("✅ Email de confirmation envoyé à", email);
      return res;
    } catch (err) {
      console.error("❌ Erreur lors de l'envoi de l'email de confirmation:", {
        message: err.message,
        response: err.response?.data,
        status: err.response?.status
      });
      throw err;
    }
  },

  sendWelcomeEmail: async (email, firstName) => {
    try {
      const res = await axios.post(`${NOTIFICATION_SERVICE_URL}/notifications/email`, {
        type: "welcome",
        email,
        tokenOrCode: firstName
      });
      console.log("✅ Email de bienvenue envoyé à", email);
      return res;
    } catch (err) {
      console.error("❌ Erreur lors de l'envoi de l'email de bienvenue:", err.message);
      throw err;
    }
  },

  sendPasswordResetEmail: async (email, code) => {
    try {
      const res = await axios.post(`${NOTIFICATION_SERVICE_URL}/notifications/email`, {
        type: "reset",
        email,
        tokenOrCode: code
      });
      console.log("✅ Email de réinitialisation envoyé à", email);
      return res;
    } catch (err) {
      console.error("❌ Erreur lors de l'envoi de l'email de réinitialisation:", err.message);
      throw err;
    }
  },

  sendPasswordResetSMS: async (phoneNumber, code) => {
    try {
      console.log(`🔄 Préparation envoi SMS pour réinitialisation, code: ${code}`);
      
      if (!FREE_MOBILE_USERNAME || !FREE_MOBILE_API_KEY) {
        console.error('❌ Configuration Free Mobile manquante');
        throw new Error('Configuration Free Mobile manquante');
      }
      
      console.log(`📤 Envoi requête vers ${NOTIFICATION_SERVICE_URL}/notifications/sms`);
      
      const response = await axios.post(`${NOTIFICATION_SERVICE_URL}/notifications/sms`, {
        username: FREE_MOBILE_USERNAME,
        apiKey: FREE_MOBILE_API_KEY,
        code: code,
        type: 'reset'
      });
      
      console.log('✅ Réponse du service de notification:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Erreur lors de l\'envoi du SMS:', error.message);
      if (error.response) {
        console.error('  Détails:', error.response.status, error.response.data);
      } else if (error.request) {
        console.error('  Pas de réponse reçue du serveur');
      }
      throw error;
    }
  }
};

module.exports = NotificationService;