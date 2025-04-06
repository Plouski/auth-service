const jwt = require('jsonwebtoken');

class OAuthController {
  static async oauthCallback(req, res) {
    try {
      const user = req.user;

      if (!user) {
        return res.status(401).json({ message: 'Utilisateur non authentifié' });
      }

      // Génére le token JWT
      const token = jwt.sign(
        { userId: user._id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      // res.redirect(`${process.env.FRONTEND_URL}/oauth-success?token=${token}`);

      res.status(200).json({
        message: 'Authentification réussie',
        token,
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName
        }
      });

    } catch (err) {
      console.error('Erreur callback OAuth :', err);
      res.status(500).json({ message: 'Erreur serveur' });
    }
  }
}

module.exports = OAuthController;