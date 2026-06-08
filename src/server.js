require('dotenv').config();
const express      = require('express');
const http         = require('http');
const { Server }   = require('socket.io');
const path         = require('path');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const Database     = require('better-sqlite3');
const helmet       = require('helmet');
const cors         = require('cors');
const rateLimit    = require('express-rate-limit');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

const JWT_SECRET = process.env.JWT_SECRET || 'zappo-secret-change-in-prod';
const PORT       = process.env.PORT || 3000;

// ── DATABASE ──────────────────────────────────────────────────
const db = new Database(path.join(__dirname, '../zappo.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id       TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    name     TEXT NOT NULL,
    password TEXT NOT NULL,
    avatar   TEXT DEFAULT '',
    online   INTEGER DEFAULT 0,
    last_seen INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS conversations (
    id         TEXT PRIMARY KEY,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS members (
    conv_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    unread  INTEGER DEFAULT 0,
    PRIMARY KEY (conv_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id        TEXT PRIMARY KEY,
    conv_id   TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    type      TEXT DEFAULT 'text',
    content   TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch('now','localtime'))
  );
  CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conv_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_members_user  ON members(user_id);
`);

// ── MIDDLEWARE ────────────────────────────────────────────────
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
const authLim = rateLimit({ windowMs: 15 * 60 * 1000, max: 20,
  message: { error: 'Too many attempts. Wait 15 minutes.' }
});
app.use('/api/', limiter);

// ── AUTH HELPERS ──────────────────────────────────────────────
function signToken(id) {
  return jwt.sign({ id }, JWT_SECRET, { expiresIn: '30d' });
}
function authMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorised' });
  }
}

// ── BLOCKED DISPOSABLE DOMAINS ────────────────────────────────
const BAD_DOMAINS = new Set([
  'mailinator.com','guerrillamail.com','10minutemail.com','tempmail.com',
  'throwam.com','yopmail.com','trashmail.com','maildrop.cc','fakeinbox.com',
  'discard.email','tempr.email','sharklasers.com','spam4.me','dispostable.com'
]);
function blockedEmail(email) {
  const d = (email||'').split('@')[1]?.toLowerCase();
  return d && BAD_DOMAINS.has(d);
}

// ══════════════════════════════════════════════════════════════
//  REST ROUTES
// ══════════════════════════════════════════════════════════════

// ── REGISTER ─────────────────────────────────────────────────
app.post('/api/register', authLim, async (req, res) => {
  const { username, name, password } = req.body;
  if (!username || !name || !password)
    return res.status(400).json({ error: 'username, name and password are required.' });
  if (username.length < 2 || !/^[a-z0-9_]+$/.test(username))
    return res.status(400).json({ error: 'Username: lowercase letters, numbers, underscore only (min 2 chars).' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const exists = db.prepare('SELECT id FROM users WHERE username=?').get(username);
  if (exists) return res.status(409).json({ error: 'Username @'+username+' is taken.' });

  const hash = await bcrypt.hash(password, 12);
  const id   = uuid();
  db.prepare('INSERT INTO users (id,username,name,password) VALUES (?,?,?,?)')
    .run(id, username, name.trim(), hash);
  res.json({ token: signToken(id), user: publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(id)) });
});

// ── LOGIN ─────────────────────────────────────────────────────
app.post('/api/login', authLim, async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username=?').get((username||'').toLowerCase());
  if (!user) return res.status(401).json({ error: 'No account found for @'+username });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok)  return res.status(401).json({ error: 'Wrong password.' });
  res.json({ token: signToken(user.id), user: publicUser(user) });
});

// ── ME ────────────────────────────────────────────────────────
app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(publicUser(user));
});

// ── FIND USER ─────────────────────────────────────────────────
app.get('/api/users/find', authMiddleware, (req, res) => {
  const { username } = req.query;
  const user = db.prepare('SELECT * FROM users WHERE username=?').get((username||'').toLowerCase());
  if (!user) return res.status(404).json({ error: 'No Zappo user found with username @'+username });
  if (user.id === req.user.id) return res.status(400).json({ error: "That's your own account." });
  res.json(publicUser(user));
});

// ── CONVERSATIONS ─────────────────────────────────────────────
app.get('/api/conversations', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT c.id, m.unread,
           u.id as ou_id, u.username as ou_username, u.name as ou_name,
           u.online as ou_online, u.last_seen as ou_last_seen,
           (SELECT content FROM messages WHERE conv_id=c.id ORDER BY created_at DESC LIMIT 1) as last_msg,
           (SELECT type    FROM messages WHERE conv_id=c.id ORDER BY created_at DESC LIMIT 1) as last_type,
           (SELECT created_at FROM messages WHERE conv_id=c.id ORDER BY created_at DESC LIMIT 1) as last_at
    FROM conversations c
    JOIN members m  ON m.conv_id=c.id AND m.user_id=?
    JOIN members m2 ON m2.conv_id=c.id AND m2.user_id!=?
    JOIN users u    ON u.id=m2.user_id
    ORDER BY last_at DESC
  `).all(req.user.id, req.user.id);
  res.json(rows.map(r => fmtConv(r)));
});

app.post('/api/conversations', authMiddleware, (req, res) => {
  const { otherUserId } = req.body;
  const other = db.prepare('SELECT * FROM users WHERE id=?').get(otherUserId);
  if (!other) return res.status(404).json({ error: 'User not found' });

  // Check existing
  const existing = db.prepare(`
    SELECT c.id FROM conversations c
    JOIN members m1 ON m1.conv_id=c.id AND m1.user_id=?
    JOIN members m2 ON m2.conv_id=c.id AND m2.user_id=?
  `).get(req.user.id, otherUserId);
  if (existing) return res.json({ id: existing.id, existing: true });

  const id = uuid();
  db.prepare('INSERT INTO conversations (id) VALUES (?)').run(id);
  db.prepare('INSERT INTO members (conv_id,user_id) VALUES (?,?)').run(id, req.user.id);
  db.prepare('INSERT INTO members (conv_id,user_id) VALUES (?,?)').run(id, otherUserId);
  res.json({ id, existing: false });
});

// ── MESSAGES ─────────────────────────────────────────────────
app.get('/api/conversations/:cid/messages', authMiddleware, (req, res) => {
  const member = db.prepare('SELECT 1 FROM members WHERE conv_id=? AND user_id=?').get(req.params.cid, req.user.id);
  if (!member) return res.status(403).json({ error: 'Forbidden' });
  const msgs = db.prepare(`
    SELECT m.*, u.name as sender_name, u.username as sender_username
    FROM messages m JOIN users u ON u.id=m.sender_id
    WHERE m.conv_id=? ORDER BY m.created_at ASC LIMIT 200
  `).all(req.params.cid);
  res.json(msgs);
});

app.post('/api/conversations/:cid/messages', authMiddleware, (req, res) => {
  const { type = 'text', content } = req.body;
  if (!content || content.length > 8000) return res.status(400).json({ error: 'Invalid content' });
  const member = db.prepare('SELECT 1 FROM members WHERE conv_id=? AND user_id=?').get(req.params.cid, req.user.id);
  if (!member) return res.status(403).json({ error: 'Forbidden' });

  const id  = uuid();
  const me  = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  const msg = { id, conv_id: req.params.cid, sender_id: req.user.id,
    sender_name: me.name, sender_username: me.username, type, content,
    created_at: Math.floor(Date.now()/1000) };
  db.prepare('INSERT INTO messages (id,conv_id,sender_id,type,content) VALUES (?,?,?,?,?)').run(id, req.params.cid, req.user.id, type, content);

  // Mark unread for other member
  db.prepare('UPDATE members SET unread=unread+1 WHERE conv_id=? AND user_id!=?').run(req.params.cid, req.user.id);

  // Emit via socket to all online members
  const others = db.prepare('SELECT user_id FROM members WHERE conv_id=? AND user_id!=?').all(req.params.cid, req.user.id);
  others.forEach(o => {
    const sid = onlineMap.get(o.user_id);
    if (sid) io.to(sid).emit('new_message', msg);
  });
  // Also echo back to sender's other devices
  const mySockets = onlineMap.getAll(req.user.id);
  mySockets.forEach(sid => io.to(sid).emit('new_message', msg));

  res.json(msg);
});

// Mark read
app.post('/api/conversations/:cid/read', authMiddleware, (req, res) => {
  db.prepare('UPDATE members SET unread=0 WHERE conv_id=? AND user_id=?').run(req.params.cid, req.user.id);
  res.json({ ok: true });
});

// ── GIPHY PROXY (avoids CORS issues) ─────────────────────────
app.get('/api/gifs', authMiddleware, async (req, res) => {
  const { q, limit = 24, offset = 0 } = req.query;
  const key = process.env.GIPHY_KEY || 'your_giphy_api_key_here';
  const endpoint = q
    ? `https://api.giphy.com/v1/gifs/search?api_key=${key}&q=${encodeURIComponent(q)}&limit=${limit}&offset=${offset}&rating=g`
    : `https://api.giphy.com/v1/gifs/trending?api_key=${key}&limit=${limit}&rating=g`;
  try {
    const r = await fetch(endpoint);
    const data = await r.json();
    res.json(data);
  } catch {
    res.status(502).json({ error: 'GIF service unavailable' });
  }
});

// ══════════════════════════════════════════════════════════════
//  SOCKET.IO  — real-time delivery
// ══════════════════════════════════════════════════════════════

// Multi-socket per user map
class MultiMap {
  constructor() { this._m = new Map(); }
  set(uid, sid) { if (!this._m.has(uid)) this._m.set(uid, new Set()); this._m.get(uid).add(sid); }
  get(uid)      { return this._m.get(uid)?.values().next().value || null; }
  getAll(uid)   { return [...(this._m.get(uid) || [])]; }
  delete(uid, sid) { this._m.get(uid)?.delete(sid); if (this._m.get(uid)?.size === 0) this._m.delete(uid); }
  has(uid)      { return this._m.has(uid) && this._m.get(uid).size > 0; }
}
const onlineMap = new MultiMap();

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { next(new Error('Unauthorised')); }
});

io.on('connection', (socket) => {
  const uid = socket.user.id;
  onlineMap.set(uid, socket.id);
  db.prepare('UPDATE users SET online=1, last_seen=? WHERE id=?').run(Date.now(), uid);

  // Notify contacts this user is online
  broadcastPresence(uid, true);

  socket.on('typing_start', ({ convId }) => {
    const others = db.prepare('SELECT user_id FROM members WHERE conv_id=? AND user_id!=?').all(convId, uid);
    others.forEach(o => { const s = onlineMap.get(o.user_id); if(s) io.to(s).emit('typing_start', { convId, userId: uid }); });
  });
  socket.on('typing_stop', ({ convId }) => {
    const others = db.prepare('SELECT user_id FROM members WHERE conv_id=? AND user_id!=?').all(convId, uid);
    others.forEach(o => { const s = onlineMap.get(o.user_id); if(s) io.to(s).emit('typing_stop', { convId, userId: uid }); });
  });

  socket.on('disconnect', () => {
    onlineMap.delete(uid, socket.id);
    if (!onlineMap.has(uid)) {
      db.prepare('UPDATE users SET online=0, last_seen=? WHERE id=?').run(Date.now(), uid);
      broadcastPresence(uid, false);
    }
  });
});

function broadcastPresence(uid, online) {
  // Find all users who share a conversation with uid
  const contacts = db.prepare(`
    SELECT DISTINCT m2.user_id FROM members m1
    JOIN members m2 ON m2.conv_id=m1.conv_id AND m2.user_id!=m1.user_id
    WHERE m1.user_id=?
  `).all(uid);
  contacts.forEach(c => {
    onlineMap.getAll(c.user_id).forEach(sid => io.to(sid).emit('presence', { userId: uid, online }));
  });
}

// ── HELPERS ───────────────────────────────────────────────────
function publicUser(u) {
  return { id: u.id, username: u.username, name: u.name, online: !!u.online, last_seen: u.last_seen };
}
function fmtConv(r) {
  return {
    id: r.id, unread: r.unread,
    other: { id: r.ou_id, username: r.ou_username, name: r.ou_name, online: !!r.ou_online, last_seen: r.ou_last_seen },
    last_msg: r.last_type === 'gif' ? '🎞️ GIF' : r.last_type === 'sticker' ? '🎭 Sticker' : (r.last_msg || ''),
    last_at: r.last_at
  };
}

// ── START ─────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`\n⚡ Zappo running → http://localhost:${PORT}`);
  console.log(`   Share your local IP so other devices can connect.`);
  console.log(`   Or deploy to Railway/Render to get a public URL.\n`);
});
