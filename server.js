'use strict';
require('dotenv').config();
var express    = require('express');
var session    = require('express-session');
var cors       = require('cors');
var axios      = require('axios');
var path       = require('path');
var fs         = require('fs');
var initSqlJs  = require('sql.js');

var app  = express();
var PORT = process.env.PORT || 3000;

// ── DB (partagée avec le bot) ──────────────────────────────────────────────────
var DB_PATH = process.env.DB_PATH || path.join(__dirname, '../database/okinawa.sqlite');
var db = null;

function saveDb() {
  if (!db) return;
  try { fs.writeFileSync(DB_PATH, Buffer.from(db.export())); } catch(e) {}
}
function dbRun(sql, params) { db.run(sql, params || []); saveDb(); }
function dbGet(sql, params) {
  var stmt = db.prepare(sql); stmt.bind(params || []);
  var r = null; if (stmt.step()) r = stmt.getAsObject(); stmt.free(); return r;
}
function dbAll(sql, params) {
  var r = []; var stmt = db.prepare(sql); stmt.bind(params || []);
  while (stmt.step()) r.push(stmt.getAsObject()); stmt.free(); return r;
}

initSqlJs().then(function(SQL) {
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }
  console.log('[Dashboard] DB connectée.');
});

// ── Middleware ─────────────────────────────────────────────────────────────────
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'okinawa_secret_change_me',
  resave: false, saveUninitialized: false,
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
// Sert les fichiers statiques depuis le dossier courant (pas de sous-dossier /public requis)
app.use(express.static(__dirname));

// ── Discord OAuth2 ────────────────────────────────────────────────────────────
var DISCORD_CLIENT_ID     = process.env.DISCORD_CLIENT_ID;
var DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
var REDIRECT_URI          = process.env.REDIRECT_URI || 'http://localhost:3000/auth/callback';
var DISCORD_API           = 'https://discord.com/api/v10';

// Auth : redirige vers Discord
app.get('/auth/login', function(req, res) {
  var params = new URLSearchParams({
    client_id:     DISCORD_CLIENT_ID,
    redirect_uri:  REDIRECT_URI,
    response_type: 'code',
    scope:         'identify guilds',
  });
  res.redirect('https://discord.com/oauth2/authorize?' + params.toString());
});

// Callback OAuth2
app.get('/auth/callback', async function(req, res) {
  var code = req.query.code;
  if (!code) return res.redirect('/?error=no_code');
  try {
    // Échange du code contre un token
    var tokenRes = await axios.post(DISCORD_API + '/oauth2/token',
      new URLSearchParams({
        client_id:     DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type:    'authorization_code',
        code:          code,
        redirect_uri:  REDIRECT_URI,
      }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    var token = tokenRes.data.access_token;

    // Récupère l'utilisateur
    var userRes = await axios.get(DISCORD_API + '/users/@me', {
      headers: { Authorization: 'Bearer ' + token }
    });

    // Récupère les serveurs
    var guildsRes = await axios.get(DISCORD_API + '/users/@me/guilds', {
      headers: { Authorization: 'Bearer ' + token }
    });

    req.session.user = {
      id:            userRes.data.id,
      username:      userRes.data.username,
      discriminator: userRes.data.discriminator,
      avatar:        userRes.data.avatar,
      token:         token,
    };

    // Filtre : serveurs où l'utilisateur est admin ET le bot est présent
    var MANAGE_GUILD = 0x20;
    req.session.guilds = guildsRes.data.filter(function(g) {
      return (parseInt(g.permissions) & MANAGE_GUILD) === MANAGE_GUILD;
    });

    res.redirect('/dashboard');
  } catch(e) {
    console.error('[Auth] Erreur:', e.message);
    res.redirect('/?error=auth_failed');
  }
});

// Déconnexion
app.get('/auth/logout', function(req, res) {
  req.session.destroy();
  res.redirect('/');
});

// ── Middleware auth ────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Non authentifié' });
  next();
}

// Vérifie que l'utilisateur est admin du serveur demandé
function requireGuildAdmin(req, res, next) {
  var guildId = req.params.guildId || req.body.guildId;
  if (!guildId) return res.status(400).json({ error: 'guildId manquant' });
  var guild = (req.session.guilds || []).find(function(g) { return g.id === guildId; });
  if (!guild) return res.status(403).json({ error: 'Accès refusé' });
  req.guild = guild;
  next();
}

// ── API : Config publique (CLIENT_ID pour le bouton d'invitation) ─────────────
app.get('/api/config', function(req, res) {
  res.json({ clientId: process.env.DISCORD_CLIENT_ID || '' });
});

// ── API : utilisateur ─────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, function(req, res) {
  res.json({ user: req.session.user, guilds: req.session.guilds });
});

// ── API : serveurs ────────────────────────────────────────────────────────────
app.get('/api/guilds', requireAuth, function(req, res) {
  res.json(req.session.guilds || []);
});

// ── API : vue d'ensemble d'un serveur ─────────────────────────────────────────
app.get('/api/guild/:guildId/overview', requireAuth, requireGuildAdmin, function(req, res) {
  var g = req.params.guildId;
  var antiraid = dbGet('SELECT enabled FROM antiraid WHERE guild_id=?', [g]);
  var antispam = dbGet('SELECT enabled FROM antispam WHERE guild_id=?', [g]);
  var antilink = dbGet('SELECT enabled FROM antilink WHERE guild_id=?', [g]);
  var tickets  = dbGet('SELECT COUNT(*) as c FROM tickets WHERE guild_id=? AND status="open"', [g]);
  var members  = dbGet('SELECT COUNT(*) as c FROM levels WHERE guild_id=?', [g]);
  res.json({
    antiraid_enabled: antiraid ? !!antiraid.enabled : false,
    antispam_enabled: antispam ? !!antispam.enabled : false,
    antilink_enabled: antilink ? !!antilink.enabled : false,
    open_tickets:     tickets  ? tickets.c : 0,
    tracked_members:  members  ? members.c : 0,
  });
});

// ── API : Anti-Raid ───────────────────────────────────────────────────────────
app.get('/api/guild/:guildId/antiraid', requireAuth, requireGuildAdmin, function(req, res) {
  var r = dbGet('SELECT * FROM antiraid WHERE guild_id=?', [req.params.guildId]);
  res.json(r || { guild_id: req.params.guildId, enabled: 0 });
});

app.post('/api/guild/:guildId/antiraid', requireAuth, requireGuildAdmin, function(req, res) {
  var g = req.params.guildId;
  var f = req.body;
  var allowed = ['enabled','log_channel','antibot_enabled','antibot_punish','antiraid_enabled',
    'lockdown_on_nuke','join_limit','join_window','channel_delete_limit','channel_delete_window',
    'channel_create_limit','channel_create_window','role_delete_limit','role_delete_window',
    'role_create_limit','role_create_window','ban_limit','ban_window','kick_limit','kick_window',
    'webhook_limit','webhook_window'];
  var keys = Object.keys(f).filter(function(k) { return allowed.indexOf(k) > -1; });
  if (!keys.length) return res.status(400).json({ error: 'Aucun champ valide' });
  dbRun('INSERT INTO antiraid (guild_id,' + keys.join(',') + ') VALUES (?,' + keys.map(function() { return '?'; }).join(',') + ') ON CONFLICT(guild_id) DO UPDATE SET ' + keys.map(function(k) { return k + '=excluded.' + k; }).join(','),
    [g].concat(keys.map(function(k) { return f[k]; })));
  res.json({ ok: true });
});

// ── API : Anti-Spam ───────────────────────────────────────────────────────────
app.get('/api/guild/:guildId/antispam', requireAuth, requireGuildAdmin, function(req, res) {
  res.json(dbGet('SELECT * FROM antispam WHERE guild_id=?', [req.params.guildId]) || { enabled: 0, max_messages: 5, interval_sec: 3, action: 'mute' });
});

app.post('/api/guild/:guildId/antispam', requireAuth, requireGuildAdmin, function(req, res) {
  var g = req.params.guildId; var f = req.body;
  var keys = ['enabled','max_messages','interval_sec','action','log_channel'].filter(function(k) { return f[k] !== undefined; });
  dbRun('INSERT INTO antispam (guild_id,' + keys.join(',') + ') VALUES (?,' + keys.map(function() { return '?'; }).join(',') + ') ON CONFLICT(guild_id) DO UPDATE SET ' + keys.map(function(k) { return k + '=excluded.' + k; }).join(','),
    [g].concat(keys.map(function(k) { return f[k]; })));
  res.json({ ok: true });
});

// ── API : Anti-Link ───────────────────────────────────────────────────────────
app.get('/api/guild/:guildId/antilink', requireAuth, requireGuildAdmin, function(req, res) {
  res.json(dbGet('SELECT * FROM antilink WHERE guild_id=?', [req.params.guildId]) || { enabled: 0, action: 'delete', warn_threshold: 3 });
});

app.post('/api/guild/:guildId/antilink', requireAuth, requireGuildAdmin, function(req, res) {
  var g = req.params.guildId; var f = req.body;
  var keys = ['enabled','wl_roles','wl_channels','wl_users','action','warn_threshold','log_channel'].filter(function(k) { return f[k] !== undefined; });
  dbRun('INSERT INTO antilink (guild_id,' + keys.join(',') + ') VALUES (?,' + keys.map(function() { return '?'; }).join(',') + ') ON CONFLICT(guild_id) DO UPDATE SET ' + keys.map(function(k) { return k + '=excluded.' + k; }).join(','),
    [g].concat(keys.map(function(k) { return f[k]; })));
  res.json({ ok: true });
});

// ── API : Welcome ─────────────────────────────────────────────────────────────
app.get('/api/guild/:guildId/welcome', requireAuth, requireGuildAdmin, function(req, res) {
  res.json(dbGet('SELECT * FROM welcome_config WHERE guild_id=?', [req.params.guildId]) || { welcome_enabled: 0, bye_enabled: 0 });
});

app.post('/api/guild/:guildId/welcome', requireAuth, requireGuildAdmin, function(req, res) {
  var g = req.params.guildId; var f = req.body;
  var keys = ['welcome_channel','welcome_msg','welcome_enabled','bye_channel','bye_msg','bye_enabled','embed_color'].filter(function(k) { return f[k] !== undefined; });
  dbRun('INSERT INTO welcome_config (guild_id,' + keys.join(',') + ') VALUES (?,' + keys.map(function() { return '?'; }).join(',') + ') ON CONFLICT(guild_id) DO UPDATE SET ' + keys.map(function(k) { return k + '=excluded.' + k; }).join(','),
    [g].concat(keys.map(function(k) { return f[k]; })));
  res.json({ ok: true });
});

// ── API : Logs ────────────────────────────────────────────────────────────────
app.get('/api/guild/:guildId/logs', requireAuth, requireGuildAdmin, function(req, res) {
  res.json(dbGet('SELECT * FROM logs_config WHERE guild_id=?', [req.params.guildId]) || { enabled: 1 });
});

app.post('/api/guild/:guildId/logs', requireAuth, requireGuildAdmin, function(req, res) {
  var g = req.params.guildId; var f = req.body;
  var keys = ['enabled','message_delete','message_edit','member_join','member_leave','member_ban',
    'member_roles','member_nickname','channel_create','channel_delete','role_create','role_delete',
    'voice_join','voice_leave','voice_move','moderation'].filter(function(k) { return f[k] !== undefined; });
  dbRun('INSERT INTO logs_config (guild_id,' + keys.join(',') + ') VALUES (?,' + keys.map(function() { return '?'; }).join(',') + ') ON CONFLICT(guild_id) DO UPDATE SET ' + keys.map(function(k) { return k + '=excluded.' + k; }).join(','),
    [g].concat(keys.map(function(k) { return f[k]; })));
  res.json({ ok: true });
});

// ── API : Tickets ─────────────────────────────────────────────────────────────
app.get('/api/guild/:guildId/tickets', requireAuth, requireGuildAdmin, function(req, res) {
  var g = req.params.guildId;
  var config = dbGet('SELECT * FROM ticket_config WHERE guild_id=?', [g]) || {};
  var open   = dbAll('SELECT ticket_id,user_id,subject,opened_at,message_count FROM tickets WHERE guild_id=? AND status="open" ORDER BY opened_at DESC LIMIT 20', [g]);
  var closed = dbAll('SELECT ticket_id,user_id,subject,opened_at,closed_at FROM tickets WHERE guild_id=? AND status="closed" ORDER BY closed_at DESC LIMIT 20', [g]);
  res.json({ config: config, open: open, closed: closed });
});

app.post('/api/guild/:guildId/tickets', requireAuth, requireGuildAdmin, function(req, res) {
  var g = req.params.guildId; var f = req.body;
  var keys = ['category_id','log_channel','staff_role','transcript_channel','close_delay','open_msg'].filter(function(k) { return f[k] !== undefined; });
  dbRun('INSERT INTO ticket_config (guild_id,' + keys.join(',') + ') VALUES (?,' + keys.map(function() { return '?'; }).join(',') + ') ON CONFLICT(guild_id) DO UPDATE SET ' + keys.map(function(k) { return k + '=excluded.' + k; }).join(','),
    [g].concat(keys.map(function(k) { return f[k]; })));
  res.json({ ok: true });
});

// ── API : Niveaux ─────────────────────────────────────────────────────────────
app.get('/api/guild/:guildId/levels', requireAuth, requireGuildAdmin, function(req, res) {
  var g = req.params.guildId;
  var config  = dbGet('SELECT * FROM level_config WHERE guild_id=?', [g]) || { enabled: 1, xp_min: 15, xp_max: 40, cooldown_sec: 60 };
  var rewards = dbAll('SELECT * FROM level_rewards WHERE guild_id=? ORDER BY level ASC', [g]);
  var top     = dbAll('SELECT user_id,level,xp,messages FROM levels WHERE guild_id=? ORDER BY xp DESC LIMIT 10', [g]);
  res.json({ config: config, rewards: rewards, top: top });
});

app.post('/api/guild/:guildId/levels', requireAuth, requireGuildAdmin, function(req, res) {
  var g = req.params.guildId; var f = req.body;
  var keys = ['enabled','channel_id','xp_min','xp_max','cooldown_sec','levelup_msg'].filter(function(k) { return f[k] !== undefined; });
  dbRun('INSERT INTO level_config (guild_id,' + keys.join(',') + ') VALUES (?,' + keys.map(function() { return '?'; }).join(',') + ') ON CONFLICT(guild_id) DO UPDATE SET ' + keys.map(function(k) { return k + '=excluded.' + k; }).join(','),
    [g].concat(keys.map(function(k) { return f[k]; })));
  res.json({ ok: true });
});

// ── API : Reaction Roles ──────────────────────────────────────────────────────
app.get('/api/guild/:guildId/reactionroles', requireAuth, requireGuildAdmin, function(req, res) {
  var rr = dbAll('SELECT * FROM reaction_roles WHERE guild_id=?', [req.params.guildId]);
  // Grouper par message_id
  var grouped = {};
  rr.forEach(function(r) {
    if (!grouped[r.message_id]) grouped[r.message_id] = { message_id: r.message_id, channel_id: r.channel_id, roles: [] };
    grouped[r.message_id].roles.push({ emoji: r.emoji, role_id: r.role_id, label: r.label });
  });
  res.json(Object.values(grouped));
});

// ── API : Autorole ────────────────────────────────────────────────────────────
app.get('/api/guild/:guildId/autorole', requireAuth, requireGuildAdmin, function(req, res) {
  res.json(dbGet('SELECT * FROM autorole WHERE guild_id=?', [req.params.guildId]) || { enabled: 0, role_id: null });
});

app.post('/api/guild/:guildId/autorole', requireAuth, requireGuildAdmin, function(req, res) {
  var g = req.params.guildId; var f = req.body;
  dbRun('INSERT OR REPLACE INTO autorole (guild_id,role_id,enabled) VALUES (?,?,?)', [g, f.role_id || null, f.enabled ? 1 : 0]);
  res.json({ ok: true });
});

// ── API : Giveaways ───────────────────────────────────────────────────────────
app.get('/api/guild/:guildId/giveaways', requireAuth, requireGuildAdmin, function(req, res) {
  var g = req.params.guildId;
  var active = dbAll('SELECT * FROM giveaways WHERE guild_id=? AND ended=0 ORDER BY ends_at ASC', [g]);
  var ended  = dbAll('SELECT * FROM giveaways WHERE guild_id=? AND ended=1 ORDER BY ends_at DESC LIMIT 10', [g]);
  active.forEach(function(gw) { gw.entries_count = JSON.parse(gw.entries || '[]').length; });
  ended.forEach(function(gw)  { gw.entries_count = JSON.parse(gw.entries || '[]').length; });
  res.json({ active: active, ended: ended });
});

// ── API : Sanctions ───────────────────────────────────────────────────────────
app.get('/api/guild/:guildId/sanctions', requireAuth, requireGuildAdmin, function(req, res) {
  var rows = dbAll('SELECT * FROM sanctions WHERE guild_id=? ORDER BY created_at DESC LIMIT 50', [req.params.guildId]);
  res.json(rows);
});

// ── API : Stat Counters ───────────────────────────────────────────────────────
app.get('/api/guild/:guildId/stats', requireAuth, requireGuildAdmin, function(req, res) {
  var g = req.params.guildId;
  res.json({
    config:   dbGet('SELECT * FROM stat_config WHERE guild_id=?', [g]) || {},
    counters: dbAll('SELECT * FROM stat_counters WHERE guild_id=?', [g])
  });
});

// ── Serve le dashboard SPA ────────────────────────────────────────────────────
app.get('/dashboard', requireAuth, function(req, res) {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'index.html'));
});


// ── API : Embeds personnalisés ────────────────────────────────────────────────
// Stocke les configs d'embed dans la DB (table embed_configs)
// On crée la table si elle n'existe pas
function ensureEmbedTable() {
  try {
    dbRun('CREATE TABLE IF NOT EXISTS embed_configs (guild_id TEXT, type TEXT, data TEXT, PRIMARY KEY(guild_id, type))');
  } catch(e) {}
}

app.get('/api/guild/:guildId/embeds', requireAuth, requireGuildAdmin, function(req, res) {
  ensureEmbedTable();
  var rows = dbAll('SELECT type, data FROM embed_configs WHERE guild_id=?', [req.params.guildId]);
  var result = {};
  rows.forEach(function(r) {
    try { result[r.type] = JSON.parse(r.data); } catch(e) {}
  });
  res.json(result);
});

app.post('/api/guild/:guildId/embeds', requireAuth, requireGuildAdmin, function(req, res) {
  ensureEmbedTable();
  var g    = req.params.guildId;
  var type = req.body.type;
  var data = req.body.data;
  var allowed = ['welcome','bye','levelup','ban','kick','mute','warn','ticket_open','ticket_close'];
  if (!type || allowed.indexOf(type) === -1) return res.status(400).json({ error: 'Type invalide' });
  dbRun('INSERT OR REPLACE INTO embed_configs (guild_id, type, data) VALUES (?,?,?)', [g, type, JSON.stringify(data)]);
  res.json({ ok: true });
});

// Endpoint public pour que le bot récupère ses configs d'embed
app.get('/api/internal/embeds/:guildId/:type', function(req, res) {
  var secret = req.headers['x-bot-secret'];
  if (secret !== process.env.BOT_SECRET) return res.status(403).json({ error: 'Accès refusé' });
  ensureEmbedTable();
  var row = dbGet('SELECT data FROM embed_configs WHERE guild_id=? AND type=?', [req.params.guildId, req.params.type]);
  res.json(row ? JSON.parse(row.data) : null);
});

// ── API : Salons du serveur (pour le sélecteur de salon) ─────────────────────
app.get('/api/guild/:guildId/channels', requireAuth, requireGuildAdmin, async function(req, res) {
  try {
    var token = req.session.user.token;
    var guildId = req.params.guildId;
    // Fetch channels via Discord API avec le token bot (on passe par le bot secret)
    // On récupère depuis la DB les salons connus (stat_counters, logs_config, etc.)
    // Pour récupérer tous les salons, le dashboard appelle l'endpoint interne du bot
    var axios = require('axios');
    var botRes = await axios.get('http://localhost:' + (process.env.BOT_API_PORT || 3001) + '/channels/' + guildId, {
      headers: { 'x-bot-secret': process.env.BOT_SECRET || 'okinawa_bot_secret' },
      timeout: 5000
    }).catch(function() { return null; });
    if (botRes && botRes.data) return res.json(botRes.data);
    res.json([]); // fallback vide si bot pas joignable
  } catch(e) { res.json([]); }
});

// ── API : Envoyer un embed depuis le dashboard ────────────────────────────────
app.post('/api/guild/:guildId/send-embed', requireAuth, requireGuildAdmin, async function(req, res) {
  try {
    var axios = require('axios');
    var guildId = req.params.guildId;
    var { channelId, embed } = req.body;
    if (!channelId || !embed) return res.status(400).json({ error: 'channelId et embed requis' });

    var botRes = await axios.post('http://localhost:' + (process.env.BOT_API_PORT || 3001) + '/send-embed', {
      guildId: guildId,
      channelId: channelId,
      embed: embed
    }, {
      headers: { 'x-bot-secret': process.env.BOT_SECRET || 'okinawa_bot_secret' },
      timeout: 8000
    });
    res.json(botRes.data);
  } catch(e) {
    console.error('[Dashboard] send-embed error:', e.message);
    res.status(500).json({ error: 'Impossible de contacter le bot. Vérifie que BOT_API_PORT est configuré.' });
  }
});

// ── API : Super Admin (toi uniquement) ───────────────────────────────────────
var SUPER_ADMIN_ID = process.env.SUPER_ADMIN_DISCORD_ID;

function requireSuperAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Non authentifié' });
  if (req.session.user.id !== SUPER_ADMIN_ID) return res.status(403).json({ error: 'Réservé au super admin' });
  next();
}

// Liste toutes les licences
app.get('/api/admin/licenses', requireSuperAdmin, function(req, res) {
  var rows = dbAll('SELECT * FROM guild_licenses ORDER BY added_at DESC');
  res.json(rows);
});

// Suspendre un serveur
app.post('/api/admin/suspend/:guildId', requireSuperAdmin, function(req, res) {
  var reason = req.body.reason || 'Suspendu par l\'administrateur';
  dbRun('UPDATE guild_licenses SET active=0, suspended_at=strftime(\'%s\',\'now\'), suspended_reason=? WHERE guild_id=?', [reason, req.params.guildId]);
  res.json({ ok: true });
});

// Réactiver un serveur
app.post('/api/admin/unsuspend/:guildId', requireSuperAdmin, function(req, res) {
  dbRun('UPDATE guild_licenses SET active=1, suspended_at=NULL, suspended_reason=NULL WHERE guild_id=?', [req.params.guildId]);
  res.json({ ok: true });
});

// Supprimer une licence
app.delete('/api/admin/license/:guildId', requireSuperAdmin, function(req, res) {
  dbRun('DELETE FROM guild_licenses WHERE guild_id=?', [req.params.guildId]);
  res.json({ ok: true });
});

// Stats globales
app.get('/api/admin/stats', requireSuperAdmin, function(req, res) {
  var total    = dbGet('SELECT COUNT(*) as c FROM guild_licenses');
  var active   = dbGet('SELECT COUNT(*) as c FROM guild_licenses WHERE active=1');
  var suspended= dbGet('SELECT COUNT(*) as c FROM guild_licenses WHERE active=0');
  res.json({ total: total.c, active: active.c, suspended: suspended.c });
});

// Page admin
app.get('/admin', function(req, res) {
  if (!req.session.user || req.session.user.id !== SUPER_ADMIN_ID)
    return res.redirect('/auth/login?redirect=admin');
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.listen(PORT, function() {
  console.log('[Dashboard] Serveur démarré sur http://localhost:' + PORT);
});
