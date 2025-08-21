const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const db = require('./db');
const { HOST, PORT, ADMIN_PASSWORD, SESSION_SECRET } = require('./config');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// --- Configuration & State Management ---
const CONFIG_FILE = path.join(__dirname, 'chat-config.json');
let chatConfig = {};

function loadChatConfig() {
    try {
        const data = fs.readFileSync(CONFIG_FILE, 'utf8');
        chatConfig = JSON.parse(data);
        console.log('Chat config loaded successfully.');
    } catch (error) {
        console.error('Error loading chat config, using defaults:', error);
        // Define default config here if file is missing or corrupt
        chatConfig = {
            assistantName: "Assistant",
            welcomeMessage: "Bonjour ! Comment puis-je vous aider ?",
            themeColor: "#f76000",
            adminAvatar: "/img/lebon.PNG",
            userAvatar: "/img/user.png",
            chatIcon: "/img/ico.png"
        };
    }
}

function saveChatConfig() {
    return new Promise((resolve, reject) => {
        fs.writeFile(CONFIG_FILE, JSON.stringify(chatConfig, null, 2), 'utf8', (err) => {
            if (err) {
                console.error('Error saving chat config:', err);
                return reject(err);
            }
            console.log('Chat config saved successfully.');
            resolve();
        });
    });
}

loadChatConfig(); // Initial load

const app = express();
app.set('trust proxy', 1); // Ajout pour faire confiance au proxy

const sessionMiddleware = session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
});

app.use(sessionMiddleware);
app.use(cors());
app.use(express.json());

// --- Multer Configuration ---

// For chat file uploads
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// For settings file uploads (avatars, sounds, etc.)
const settingsStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        let dest = 'public/';
        if (['adminAvatar', 'userAvatar', 'chatIcon'].includes(file.fieldname)) {
            dest += 'img/';
        } else if (file.fieldname.startsWith('sound')) {
            dest = path.join(dest, 'sounds');
        } else {
            // Si le type de fichier est audio, le placer dans le dossier des sons par défaut
            if (file.mimetype.startsWith('audio/')) {
                 dest = path.join(dest, 'sounds');
            }
        }
        cb(null, dest);
    },
    filename: function (req, file, cb) {
        // Keep original filename for settings files for predictability
        cb(null, file.originalname);
    }
});
const uploadSettings = multer({ storage: settingsStorage });


const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: 'https://cha-server.pages.dev',
        methods: ['GET', 'POST']
    }
});

io.use((socket, next) => {
    sessionMiddleware(socket.request, {}, next);
});

// --- HTTP Routes ---

// Public route to get client-facing config
app.get('/api/public-config', (req, res) => {
    res.json({
        assistantName: chatConfig.assistantName,
        themeColor: chatConfig.themeColor,
        adminAvatar: chatConfig.adminAvatar,
        userAvatar: chatConfig.userAvatar,
        chatIcon: chatConfig.chatIcon,
        newMessageSoundClient: chatConfig.newMessageSoundClient
    });
});

app.post('/login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) {
        req.session.isAdmin = true;
        res.json({ message: 'Connexion réussie' });
    } else {
        res.status(401).json({ error: 'Mot de passe incorrect' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login.html'));
});

const checkAdminAuth = (req, res, next) => {
    if (req.session.isAdmin) return next();
    res.status(403).redirect('/login.html');
};

app.get('/colisadmin', checkAdminAuth, (req, res) => {
    res.sendFile(__dirname + '/public/colisadmin.html');
});

// --- Settings API Routes (Admin only) ---
app.get('/api/settings', checkAdminAuth, (req, res) => {
    res.json(chatConfig);
});

app.post('/api/settings', checkAdminAuth, uploadSettings.fields([
    { name: 'adminAvatar', maxCount: 1 },
    { name: 'userAvatar', maxCount: 1 },
    { name: 'chatIcon', maxCount: 1 },
    { name: 'newMessageSoundAdmin', maxCount: 1 },
    { name: 'newUserSoundAdmin', maxCount: 1 },
    { name: 'statusSoundAdmin', maxCount: 1 },
    { name: 'newMessageSoundClient', maxCount: 1 }
]), async (req, res) => {
    console.log('--- Received request on /api/settings ---');
    console.log('Body:', req.body);
    
    if (!req.files || Object.keys(req.files).length === 0) {
        console.log('Files: Aucun fichier n\'a été reçu par le serveur.');
    } else {
        console.log('Files:', req.files);
    }

    try {
        // Update text-based settings from req.body
        if (req.body.assistantName) chatConfig.assistantName = req.body.assistantName;
        if (req.body.welcomeMessage) chatConfig.welcomeMessage = req.body.welcomeMessage;
        if (req.body.themeColor) chatConfig.themeColor = req.body.themeColor;

        // Update file paths if new files were uploaded
        if (req.files && req.files['adminAvatar']) {
            chatConfig.adminAvatar = '/img/' + req.files['adminAvatar'][0].filename;
        }
        if (req.files && req.files['userAvatar']) {
            chatConfig.userAvatar = '/img/' + req.files['userAvatar'][0].filename;
        }
        if (req.files && req.files['chatIcon']) {
            chatConfig.chatIcon = '/img/' + req.files['chatIcon'][0].filename;
        }
        if (req.files && req.files['newMessageSoundAdmin']) {
            chatConfig.newMessageSoundAdmin = '/sounds/' + req.files['newMessageSoundAdmin'][0].filename;
        }
        if (req.files && req.files['newUserSoundAdmin']) {
            chatConfig.newUserSoundAdmin = '/sounds/' + req.files['newUserSoundAdmin'][0].filename;
        }
        if (req.files && req.files['statusSoundAdmin']) {
            chatConfig.statusSoundAdmin = '/sounds/' + req.files['statusSoundAdmin'][0].filename;
        }
        if (req.files && req.files['newMessageSoundClient']) {
            chatConfig.newMessageSoundClient = '/sounds/' + req.files['newMessageSoundClient'][0].filename;
        }

        await saveChatConfig();
        console.log('Settings updated and saved successfully.');
        res.json({ message: 'Settings updated successfully.' });
    } catch (error) {
        console.error('--- ERROR in /api/settings ---', error);
        sendError(res, 'Failed to update settings.');
    }
});

app.get('/api/conversations', checkAdminAuth, async (req, res) => {
    try {
        const [rows] = await db.query(
            `SELECT 
                m.conversation_id, 
                MAX(m.created_at) AS last_msg,
                a.alias
             FROM messages m
             LEFT JOIN ip_aliases a ON m.conversation_id = a.ip_address
             GROUP BY m.conversation_id, a.alias
             ORDER BY last_msg DESC`
        );
        res.json(rows);
    } catch (err) {
        sendError(res, err);
    }
});

app.use(express.static('public'));

const sendError = (res, err) => {
    console.error(err);
    res.status(500).json({ error: 'Erreur interne du serveur' });
};

app.get('/api/messages/:id', async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC',
            [req.params.id]
        );
        res.json(rows);
    } catch (err) {
        sendError(res, err);
    }
});

app.get('/api/export/:conversationId', checkAdminAuth, async (req, res) => {
    try {
        const { conversationId } = req.params;
        const [messages] = await db.query(
            'SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC',
            [conversationId]
        );

        if (messages.length === 0) {
            return res.status(404).send('Aucun message trouvé pour cette conversation.');
        }

        let fileContent = `Historique de la conversation : ${conversationId}\n\n`;

        messages.forEach(msg => {
            const timestamp = new Date(msg.created_at).toLocaleString('fr-FR');
            let content = msg.message || '';
            if (msg.is_html) {
                // Simplification basique du HTML pour la lisibilité en texte brut
                content = content.replace(/<[^>]+>/g, '');
            }
            if (msg.file_name) {
                content += ` (Fichier joint: ${msg.file_name})`;
            }
            fileContent += `[${timestamp}] ${msg.sender}: ${content.trim()}\n`;
        });

        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="conversation-${conversationId}.txt"`);
        res.send(fileContent);
    } catch (err) {
        sendError(res, err);
    }
});

app.post('/api/alias', checkAdminAuth, async (req, res) => {
    try {
        const { ip_address, alias } = req.body;
        if (!ip_address) {
            return res.status(400).json({ error: 'ip_address is required.' });
        }

        if (alias) {
            // Insérer ou mettre à jour l'alias
            await db.query(
                'INSERT INTO ip_aliases (ip_address, alias) VALUES (?, ?) ON DUPLICATE KEY UPDATE alias = ?',
                [ip_address, alias, alias]
            );
        } else {
            // Si l'alias est vide, le supprimer
            await db.query('DELETE FROM ip_aliases WHERE ip_address = ?', [ip_address]);
        }

        res.json({ message: 'Alias mis à jour avec succès.' });
    } catch (err) {
        sendError(res, err);
    }
});

app.delete('/api/conversations/:conversationId', checkAdminAuth, async (req, res) => {
    try {
        const { conversationId } = req.params;
        await db.query('DELETE FROM messages WHERE conversation_id = ?', [conversationId]);
        res.json({ message: 'Conversation supprimée avec succès.' });
    } catch (err) {
        sendError(res, err);
    }
});

app.post('/api/details', checkAdminAuth, async (req, res) => {
    try {
        const { conversationId, details } = req.body;
        if (!conversationId || details === undefined) {
            return res.status(400).json({ error: 'conversationId and details are required.' });
        }

        // Mettre à jour les détails pour tous les messages de cette conversation
        await db.query(
            'UPDATE messages SET details = ? WHERE conversation_id = ?',
            [details, conversationId]
        );

        res.json({ message: 'Détails mis à jour avec succès.' });
    } catch (err) {
        sendError(res, err);
    }
});

app.post('/api/upload', upload.single('file'), async (req, res) => {
    try {
        const { conversationId, sender, message } = req.body;

        if (!req.file) {
            return res.status(400).json({ error: 'Aucun fichier n\'a été envoyé.' });
        }

        const { originalname, filename } = req.file;

        const [result] = await db.query(
            'INSERT INTO messages (conversation_id, sender, message, file_name, file_path) VALUES (?, ?, ?, ?, ?)',
            [conversationId, sender, message || null, originalname, filename]
        );
        const [rows] = await db.query('SELECT * FROM messages WHERE id = ?', [result.insertId]);
        const messageData = rows[0];

        io.to(messageData.conversation_id).emit('message', messageData);

        if (sender === 'user') {
            io.to('admins').emit('new_message_alert', {
                conversation_id: messageData.conversation_id,
                last_msg: messageData.created_at,
                sender: 'user'
            });
        }

        res.json(messageData);
    } catch (err) {
        console.error('Erreur lors de l\'upload du fichier:', err);
        res.status(500).json({ error: 'Erreur interne du serveur lors de l\'upload.' });
    }
});

// --- Logique Socket.IO ---
const connectedUsers = new Map();

// ✅ Variable pour suivre le statut de l'admin
let adminIsOnline = false;

async function updateSupportStatus() {
    const adminSockets = await io.in('admins').allSockets();
    adminIsOnline = adminSockets.size > 0;
    const status = adminIsOnline ? 'online' : 'offline';
    io.emit('support_status_change', { status });
    console.log(`Support status updated to: ${status}`);
}

io.on('connection', (socket) => {
    console.log('Socket connected:', socket.id);
    const session = socket.request.session;
    socket.isAdmin = session.isAdmin || false;

    if (socket.isAdmin) {
        console.log('An admin connected:', socket.id);
        socket.join('admins');
        updateSupportStatus();
        
        // Mettre à jour le statut de l'admin pour le client qui vient de se connecter
        io.to(socket.id).emit('support_status_change', { status: 'online' });

        for (const [convId, _] of connectedUsers) {
            socket.emit('user_status_change', { conversationId: convId, status: 'online' });
        }
    }

    // ✅ Événement pour que le client demande le statut du support
    socket.on('get_support_status', () => {
        io.to(socket.id).emit('support_status_change', { status: adminIsOnline ? 'online' : 'offline' });
    });

    // Nouvelle logique d'identification par IP pour les utilisateurs normaux
    if (!socket.isAdmin) {
        // Utilise l'IP comme identifiant unique. On nettoie pour les cas comme ::ffff:127.0.0.1
        const ip = (socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || 'unknown').split(',')[0].trim();
        const conversationId = ip.includes('::ffff:') ? ip.split(':').pop() : ip;

        console.log(`User connected with IP: ${ip}, Conversation ID: ${conversationId}`);
        
        socket.conversationId = conversationId;
        socket.join(conversationId);

        // Informer le client de son ID de conversation
        socket.emit('session_initialized', { conversationId });

        // Logique pour gérer un nouvel utilisateur/conversation
        (async () => {
            connectedUsers.set(conversationId, socket.id);
            io.to('admins').emit('user_status_change', { conversationId, status: 'online' });

            const [rows] = await db.query('SELECT 1 FROM messages WHERE conversation_id = ? LIMIT 1', [conversationId]);
            if (rows.length === 0) {
                console.log(`New conversation started for ${conversationId}`);
                const systemMessage = '👋';
                await db.query('INSERT INTO messages (conversation_id, sender, message) VALUES (?, ?, ?)', [conversationId, 'system', systemMessage]);
                io.to('admins').emit('new_conversation_alert', { conversation_id: conversationId, last_msg: new Date().toISOString(), sender: 'system' });
                
                setTimeout(async () => {
                    // Use the welcome message from the loaded config
                    const welcomeMessage =`<div style="text-align:center ; background-color:#fff; padding:4px ;max-width:100%; border-radius:10px;"> <img src="${require('./config').SERVER_URL}`+chatConfig.chatIcon+`" height="40px" /> </div>` + chatConfig.welcomeMessage  || "Bonjour ! Comment puis-je vous aider ?";
                    
                    const [result] = await db.query(
                        'INSERT INTO messages (conversation_id, sender, message, is_html) VALUES (?, ?, ?, ?)',
                        [conversationId, 'admin', welcomeMessage, 1] // Assuming welcome message can be HTML
                    );
                    
                    const [rows] = await db.query('SELECT * FROM messages WHERE id = ?', [result.insertId]);
                    const messageData = rows[0];
                    io.to(conversationId).emit('message', messageData);
                }, 10000);
            }
        })();
    }

    // Permet à un admin de rejoindre une room de conversation spécifique
    socket.on('join', ({ conversationId }) => {
        if (socket.isAdmin && conversationId) {
            console.log(`Admin ${socket.id} joining conversation ${conversationId}`);
            socket.join(conversationId);
        }
    });

    // Permet à un admin de quitter une room pour ne plus recevoir les messages
    socket.on('leave', ({ conversationId }) => {
        if (socket.isAdmin && conversationId) {
            console.log(`Admin ${socket.id} leaving conversation ${conversationId}`);
            socket.leave(conversationId);
        }
    });

    socket.on('message', async (msg) => {
        try {
            const sender = socket.isAdmin ? 'admin' : 'user';
            let conversationId;

            // Déterminer l'ID de conversation en fonction du rôle
            if (sender === 'admin') {
                // Pour l'admin, l'ID vient du message qu'il envoie
                conversationId = msg.conversationId;
            } else {
                // Pour l'utilisateur, l'ID est attaché à sa connexion (socket)
                conversationId = socket.conversationId;
            }

            if (!conversationId) {
                return console.error('Message reçu sans ID de conversation valide.');
            }

            const { message } = msg;

            const [result] = await db.query(
                'INSERT INTO messages (conversation_id, sender, message) VALUES (?, ?, ?)',
                [conversationId, sender, message]
            );
            const [rows] = await db.query('SELECT * FROM messages WHERE id = ?', [result.insertId]);
            const messageData = rows[0];

            // Envoyer le message à tous les participants de la conversation (utilisateur et admin si actif)
            io.to(conversationId).emit('message', messageData);

            // Si l'utilisateur envoie un message, alerter tous les admins
            if (sender === 'user') {
                io.to('admins').emit('new_message_alert', {
                    conversation_id: conversationId,
                    last_msg: messageData.created_at,
                    sender: 'user'
                });
            }
        } catch (err) {
            console.error('Erreur lors du traitement du message:', err);
        }
    });

    socket.on('live_typing', (data) => {
        const conversationId = socket.isAdmin ? data.conversationId : socket.conversationId;
        if (!conversationId) return;

        const text = data.text;

        if (socket.isAdmin) {
            // L'admin envoie le typing à une conversation spécifique
            io.to(conversationId).emit('live_typing', { conversationId, text });
        } else {
            // L'utilisateur envoie le typing à tous les admins
            io.to('admins').emit('live_typing', { conversationId, text });
        }
    });

    socket.on('message_read', async ({ messageId }) => {
        try {
            if (socket.conversationId && messageId) {
                const [result] = await db.query(
                    'UPDATE messages SET is_read = 1 WHERE id = ? AND conversation_id = ? AND sender = "admin"',
                    [messageId, socket.conversationId]
                );

                // Si une ligne a bien été mise à jour, on notifie les admins
                if (result.affectedRows > 0) {
                    io.to('admins').emit('message_was_read', { 
                        messageId, 
                        conversationId: socket.conversationId 
                    });
                }
            }
        } catch (err) {
            console.error('Erreur lors de la mise à jour du statut de lecture:', err);
        }
    });

    socket.on('user_came_back_online', () => {
        if (socket.conversationId) {
            console.log(`User ${socket.conversationId} came back online.`);
            connectedUsers.set(socket.conversationId, socket.id);
            io.to('admins').emit('user_status_change', { conversationId: socket.conversationId, status: 'online' });
        }
    });

    socket.on('edit_message', async ({ messageId, conversationId, newMessage }) => {
        if (!socket.isAdmin) return; // Sécurité : seul l'admin peut modifier

        try {
            // Mettre à jour le message dans la base de données
            await db.query(
                'UPDATE messages SET message = ?, is_edited = 1 WHERE id = ? AND sender = "admin"',
                [newMessage, messageId]
            );
            // Diffuser la mise à jour à tous les clients dans la conversation
            io.to(conversationId).emit('message_edited', { messageId, newMessage });
        } catch (err) {
            console.error('Erreur lors de la modification du message:', err);
        }
    });

    socket.on('delete_message', async ({ messageId, conversationId }) => {
        if (!socket.isAdmin) return; // Sécurité : seul l'admin peut supprimer

        try {
            // Supprimer le message de la base de données
            await db.query(
                'DELETE FROM messages WHERE id = ? AND sender = "admin"',
                [messageId]
            );
            // Informer tous les clients de la suppression
            io.to(conversationId).emit('message_deleted', { messageId });
        } catch (err) {
            console.error('Erreur lors de la suppression du message:', err);
        }
    });

    socket.on('disconnect', () => {
        console.log('Socket disconnected:', socket.id);
        if (socket.isAdmin) {
            updateSupportStatus();
        } else if (socket.conversationId) {
            connectedUsers.delete(socket.conversationId);
            io.to('admins').emit('user_status_change', {
                conversationId: socket.conversationId,
                status: 'offline'
            });
        }
    });
});

server.listen(PORT, HOST, () => {
    console.log(`Chat server listening on http://${HOST}:${PORT}`);
});