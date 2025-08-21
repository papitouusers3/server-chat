Chat Application (Node.js + Socket.IO + MySQL)
=============================================

Contenu:
- server.js        (Node.js server)
- db.js            (MySQL connection pool)
- package.json
- public/
    - client.html  (interface utilisateur)
    - admin.html   (interface admin)
    - style.css
    - sounds/new-message.wav
- sql/init.sql     (script pour créer la table)

Installation (Windows / Linux / Mac):
1. Installer Node.js (>=16) et MySQL.
2. Créer la base de données `chatdb` dans MySQL:
   - Connectez-vous à MySQL et exécutez le script sql/init.sql
     (mysql -u root -p < sql/init.sql) ou via phpMyAdmin.

3. Modifier db.js si nécessaire (host/user/password/database).

4. Installer les dépendances:
   cd <dossier-du-projet>
   npm install

5. Lancer le serveur:
   npm start

6. Ouvrir dans le navigateur:
   - http://localhost:3000/client.html  (interface utilisateur)
   - http://localhost:3000/admin.html   (interface admin)

Notes:
- Le son de notification est public/sounds/new-message.wav
- En production, protégez admin.html (authentification).
