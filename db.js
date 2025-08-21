const mysql = require('mysql2/promise');

// Utilise les variables d'environnement pour la production,
// avec des valeurs par défaut pour le développement local.
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'sql112.infinityfree.com',
  user: process.env.DB_USER || 'if0_39761904',
  password: process.env.DB_PASSWORD || 'Gobnf0ssmMVXV',
  database: process.env.DB_DATABASE || 'if0_39761904_chatdb',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = pool;
