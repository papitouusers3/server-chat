// config.js
// Ce fichier centralise la configuration du serveur.
// Pour la production, il est recommandé d'utiliser des variables d'environnement.

const HOST = process.env.HOST || '0.0.0.0'; // écouter toutes les IP
const PORT = process.env.PORT || 3001; // Render fournit automatiquement PORT
const SERVER_URL = `http://${HOST}:${PORT}`;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Stevy05@';
const SESSION_SECRET = process.env.SESSION_SECRET || 'xgfttr5454gfgfgfg-45544ghgff-gFGFfgfg23242424éKJKHGHGhg-FFGGFgf';

module.exports = {
    HOST,
    PORT,
    SERVER_URL,
    ADMIN_PASSWORD,
    SESSION_SECRET,
};