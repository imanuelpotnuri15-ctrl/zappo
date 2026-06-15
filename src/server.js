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
const webpush      = require('web-push');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' }, maxHttpBufferSize: 10e6 });

const JWT_SECRET = process.env.JWT_SECRET || 'zappo-secret-change-in-prod';
const PORT       = process.env.PORT || 3000;

// ── WEB PUSH SETUP ────────────────────────────────────────────────────────────
// Generate VAPID keys once: node -e "const wp=require('web-push');console.log(wp.generateVAPIDKeys())"
// Then add VAPID_PUBLIC and VAPID_PRIVATE to Railway environment variables
const VAPID_PUBLIC  = process.env.VAPID_PUBLIC  || '';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE || '';
if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webpush.setVapidDetails('mailto:zappo@zappo.app', VAPID_PUBLIC, VAPID_PRIVATE);
}

// ── DATABASE ──────────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, '../zappo.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        TEXT PRIMARY KEY,
    username  TEXT UNIQUE NOT NULL,
    name      TEXT NOT NULL,
    password  TEXT NOT NULL,
    online    INTEGER DEFAULT 0,
    last_seen INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS push_subscriptions (
    id      TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    sub     TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS conversations (
    id         TEXT PRIMARY KEY,
    is_group   INTEGER DEFAULT 0,
    name       TEXT,
    created_by TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS members (
    conv_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    unread  INTEGER DEFAULT 0,
    PRIMARY KEY (conv_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id               TEXT PRIMARY KEY,
    conv_id          TEXT NOT NULL,
    sender_id        TEXT NOT NULL,
    type             TEXT DEFAULT 'text',
    content          TEXT NOT NULL,
    reply_to         TEXT DEFAULT NULL,
    reply_to_name    TEXT DEFAULT NULL,
    reply_to_content TEXT DEFAULT NULL,
    edited           INTEGER DEFAULT 0,
    deleted_for_all  INTEGER DEFAULT 0,
    created_at       INTEGER DEFAULT (unixepoch('now','localtime'))
  );
  CREATE TABLE IF NOT EXISTS deleted_for_me (
    msg_id  TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (msg_id, user_id)
  );
  CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conv_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_members_user  ON members(user_id);
  CREATE INDEX IF NOT EXISTS idx_push_user     ON push_subscriptions(user_id);
`);

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, '../public')));

const limiter = rateLimit({ windowMs: 15*60*1000, max: 500 });
const authLim = rateLimit({ windowMs: 15*60*1000, max: 20, message: { error: 'Too many attempts.' } });
app.use('/api/', limiter);

// ── AUTH HELPERS ──────────────────────────────────────────────────────────────
function signToken(id) { return jwt.sign({ id }, JWT_SECRET, { expiresIn: '30d' }); }
function authMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Unauthorised' }); }
}

// ── PUSH NOTIFICATION HELPER ──────────────────────────────────────────────────
async function pushNotify(userId, title, body, url='/') {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) return;
  const subs = db.prepare('SELECT sub FROM push_subscriptions WHERE user_id=?').all(userId);
  const payload = JSON.stringify({ title, body, url, tag: 'zappo-'+userId });
  for (const row of subs) {
    try {
      await webpush.sendNotification(JSON.parse(row.sub), payload);
    } catch (e) {
      if (e.statusCode === 410 || e.statusCode === 404) {
        db.prepare('DELETE FROM push_subscriptions WHERE user_id=? AND sub=?').run(userId, row.sub);
      }
    }
  }
}

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────
app.post('/api/register', authLim, async (req, res) => {
  const { username, name, password } = req.body;
  if (!username || !name || !password) return res.status(400).json({ error: 'All fields required.' });
  if (username.length < 2 || !/^[a-z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username: lowercase letters, numbers, underscore only.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (db.prepare('SELECT id FROM users WHERE username=?').get(username)) return res.status(409).json({ error: 'Username @'+username+' is already taken.' });
  const hash = await bcrypt.hash(password, 12);
  const id = uuid();
  db.prepare('INSERT INTO users (id,username,name,password) VALUES (?,?,?,?)').run(id, username, name.trim(), hash);
  res.json({ token: signToken(id), user: publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(id)) });
});

app.post('/api/login', authLim, async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username=?').get((username||'').toLowerCase());
  if (!user) return res.status(401).json({ error: 'No account found for @'+username });
  if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Wrong password.' });
  res.json({ token: signToken(user.id), user: publicUser(user) });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(publicUser(user));
});

app.get('/api/users/find', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE username=?').get((req.query.username||'').toLowerCase());
  if (!user) return res.status(404).json({ error: 'No Zappo user found with that username.' });
  if (user.id === req.user.id) return res.status(400).json({ error: "That's your own account." });
  res.json(publicUser(user));
});

// ── VAPID PUBLIC KEY (for frontend) ──────────────────────────────────────────
app.get('/api/push/vapid-key', authMiddleware, (req, res) => {
  res.json({ key: VAPID_PUBLIC || null });
});

// ── PUSH SUBSCRIPTION ─────────────────────────────────────────────────────────
app.post('/api/push/subscribe', authMiddleware, (req, res) => {
  const { subscription } = req.body;
  if (!subscription) return res.status(400).json({ error: 'Subscription required' });
  const subStr = JSON.stringify(subscription);
  const exists = db.prepare('SELECT id FROM push_subscriptions WHERE user_id=? AND sub=?').get(req.user.id, subStr);
  if (!exists) {
    db.prepare('INSERT INTO push_subscriptions (id,user_id,sub) VALUES (?,?,?)').run(uuid(), req.user.id, subStr);
  }
  res.json({ ok: true });
});

app.post('/api/push/unsubscribe', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM push_subscriptions WHERE user_id=?').run(req.user.id);
  res.json({ ok: true });
});

// ── CONVERSATION ROUTES ───────────────────────────────────────────────────────
app.get('/api/conversations', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT c.id, c.is_group, c.name as grp_name, m.unread,
           u.id as ou_id, u.username as ou_username, u.name as ou_name,
           u.online as ou_online, u.last_seen as ou_last_seen,
           (SELECT content    FROM messages WHERE conv_id=c.id AND deleted_for_all=0 ORDER BY created_at DESC LIMIT 1) as last_msg,
           (SELECT type       FROM messages WHERE conv_id=c.id AND deleted_for_all=0 ORDER BY created_at DESC LIMIT 1) as last_type,
           (SELECT created_at FROM messages WHERE conv_id=c.id AND deleted_for_all=0 ORDER BY created_at DESC LIMIT 1) as last_at
    FROM conversations c
    JOIN members m ON m.conv_id=c.id AND m.user_id=?
    LEFT JOIN members m2 ON m2.conv_id=c.id AND m2.user_id!=? AND c.is_group=0
    LEFT JOIN users u ON u.id=m2.user_id
    ORDER BY last_at DESC
  `).all(req.user.id, req.user.id);
  res.json(rows.map(r => fmtConv(r)));
});

app.post('/api/conversations', authMiddleware, (req, res) => {
  const { otherUserId } = req.body;
  const other = db.prepare('SELECT * FROM users WHERE id=?').get(otherUserId);
  if (!other) return res.status(404).json({ error: 'User not found' });
  const existing = db.prepare(`
    SELECT c.id FROM conversations c
    JOIN members m1 ON m1.conv_id=c.id AND m1.user_id=?
    JOIN members m2 ON m2.conv_id=c.id AND m2.user_id=?
    WHERE c.is_group=0
  `).get(req.user.id, otherUserId);
  if (existing) return res.json({ id: existing.id, existing: true });
  const id = uuid();
  db.prepare('INSERT INTO conversations (id,is_group) VALUES (?,0)').run(id);
  db.prepare('INSERT INTO members (conv_id,user_id) VALUES (?,?)').run(id, req.user.id);
  db.prepare('INSERT INTO members (conv_id,user_id) VALUES (?,?)').run(id, otherUserId);
  res.json({ id, existing: false });
});

// ── GROUP ROUTES ──────────────────────────────────────────────────────────────
app.post('/api/groups', authMiddleware, (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Group name required.' });
  const convId = uuid();
  db.prepare('INSERT INTO conversations (id,is_group,name,created_by) VALUES (?,1,?,?)').run(convId, name.trim(), req.user.id);
  db.prepare('INSERT INTO members (conv_id,user_id) VALUES (?,?)').run(convId, req.user.id);
  res.json({ conv_id: convId, name: name.trim() });
});

app.post('/api/groups/:convId/join', authMiddleware, (req, res) => {
  const conv = db.prepare('SELECT * FROM conversations WHERE id=? AND is_group=1').get(req.params.convId);
  if (!conv) return res.status(404).json({ error: 'Group not found.' });
  const already = db.prepare('SELECT 1 FROM members WHERE conv_id=? AND user_id=?').get(req.params.convId, req.user.id);
  if (!already) {
    db.prepare('INSERT INTO members (conv_id,user_id) VALUES (?,?)').run(req.params.convId, req.user.id);
    const joiner = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    const members = db.prepare('SELECT user_id FROM members WHERE conv_id=? AND user_id!=?').all(req.params.convId, req.user.id);
    members.forEach(m => { onlineMap.getAll(m.user_id).forEach(sid => io.to(sid).emit('member_joined', { convId: req.params.convId, user: publicUser(joiner) })); });
  }
  res.json({ success: true, conv_id: req.params.convId });
});

// ── MESSAGE ROUTES ────────────────────────────────────────────────────────────
app.get('/api/conversations/:cid/messages', authMiddleware, (req, res) => {
  const member = db.prepare('SELECT 1 FROM members WHERE conv_id=? AND user_id=?').get(req.params.cid, req.user.id);
  if (!member) return res.status(403).json({ error: 'Forbidden' });
  const deleted = db.prepare('SELECT msg_id FROM deleted_for_me WHERE user_id=?').all(req.user.id).map(r => r.msg_id);
  const msgs = db.prepare(`
    SELECT m.*, u.name as sender_name, u.username as sender_username
    FROM messages m JOIN users u ON u.id=m.sender_id
    WHERE m.conv_id=? AND m.deleted_for_all=0
    ORDER BY m.created_at ASC LIMIT 200
  `).all(req.params.cid).filter(m => !deleted.includes(m.id));
  res.json(msgs);
});

app.post('/api/conversations/:cid/messages', authMiddleware, async (req, res) => {
  const { type='text', content, reply_to, reply_to_name, reply_to_content } = req.body;
  if (!content || content.length > 15000000) return res.status(400).json({ error: 'Invalid content' });
  const member = db.prepare('SELECT 1 FROM members WHERE conv_id=? AND user_id=?').get(req.params.cid, req.user.id);
  if (!member) return res.status(403).json({ error: 'Forbidden' });
  const id  = uuid();
  const me  = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  const now = Math.floor(Date.now()/1000);
  db.prepare('INSERT INTO messages (id,conv_id,sender_id,type,content,reply_to,reply_to_name,reply_to_content,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
    .run(id, req.params.cid, req.user.id, type, content, reply_to||null, reply_to_name||null, reply_to_content||null, now);
  db.prepare('UPDATE members SET unread=unread+1 WHERE conv_id=? AND user_id!=?').run(req.params.cid, req.user.id);
  const msg = { id, conv_id:req.params.cid, sender_id:req.user.id, sender_name:me.name, sender_username:me.username, type, content, reply_to:reply_to||null, reply_to_name:reply_to_name||null, reply_to_content:reply_to_content||null, edited:0, created_at:now };
  // Emit socket to all members
  const allMembers = db.prepare('SELECT user_id FROM members WHERE conv_id=?').all(req.params.cid);
  allMembers.forEach(m => { onlineMap.getAll(m.user_id).forEach(sid => io.to(sid).emit('new_message', msg)); });
  // Push notification to OFFLINE members
  const conv = db.prepare('SELECT * FROM conversations WHERE id=?').get(req.params.cid);
  const notifBody = type === 'image' ? '🖼️ Image' : type === 'gif' ? '🎞️ GIF' : type === 'sticker' ? '🎭 Sticker' : content.slice(0, 100);
  for (const m of allMembers) {
    if (m.user_id !== req.user.id && !onlineMap.has(m.user_id)) {
      await pushNotify(
        m.user_id,
        `${me.name} ${conv.is_group ? '('+conv.name+')' : ''}`,
        notifBody,
        '/?conv='+req.params.cid
      );
    }
  }
  res.json(msg);
});

app.post('/api/conversations/:cid/read', authMiddleware, (req, res) => {
  db.prepare('UPDATE members SET unread=0 WHERE conv_id=? AND user_id=?').run(req.params.cid, req.user.id);
  res.json({ ok: true });
});

// ── EDIT MESSAGE ──────────────────────────────────────────────────────────────
app.patch('/api/messages/:id', authMiddleware, (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Content required' });
  const msg = db.prepare('SELECT * FROM messages WHERE id=? AND sender_id=?').get(req.params.id, req.user.id);
  if (!msg) return res.status(403).json({ error: 'Cannot edit this message.' });
  db.prepare('UPDATE messages SET content=?, edited=1 WHERE id=?').run(content.trim(), req.params.id);
  const members = db.prepare('SELECT user_id FROM members WHERE conv_id=?').all(msg.conv_id);
  members.forEach(m => { onlineMap.getAll(m.user_id).forEach(sid => io.to(sid).emit('message_edited', { id: req.params.id, conv_id: msg.conv_id, content: content.trim() })); });
  res.json({ ok: true });
});

// ── DELETE MESSAGE ────────────────────────────────────────────────────────────
app.delete('/api/messages/:id', authMiddleware, (req, res) => {
  const { scope } = req.body;
  const msg = db.prepare('SELECT * FROM messages WHERE id=?').get(req.params.id);
  if (!msg) return res.status(404).json({ error: 'Message not found.' });
  if (scope === 'all') {
    if (msg.sender_id !== req.user.id) return res.status(403).json({ error: 'Can only delete your own messages for everyone.' });
    db.prepare('UPDATE messages SET deleted_for_all=1 WHERE id=?').run(req.params.id);
    const members = db.prepare('SELECT user_id FROM members WHERE conv_id=?').all(msg.conv_id);
    members.forEach(m => { onlineMap.getAll(m.user_id).forEach(sid => io.to(sid).emit('message_deleted', { id: req.params.id, conv_id: msg.conv_id })); });
  } else {
    db.prepare('INSERT OR IGNORE INTO deleted_for_me (msg_id,user_id) VALUES (?,?)').run(req.params.id, req.user.id);
  }
  res.json({ ok: true });
});

// ── GIPHY PROXY ───────────────────────────────────────────────────────────────
app.get('/api/gifs', authMiddleware, async (req, res) => {
  const { q, limit=24 } = req.query;
  const key = process.env.GIPHY_KEY || '';
  if (!key || key === 'your_giphy_api_key_here') return res.json({ data: [] });
  const url = q
    ? `https://api.giphy.com/v1/gifs/search?api_key=${key}&q=${encodeURIComponent(q)}&limit=${limit}&rating=g`
    : `https://api.giphy.com/v1/gifs/trending?api_key=${key}&limit=${limit}&rating=g`;
  try { const r = await fetch(url); res.json(await r.json()); }
  catch { res.status(502).json({ data: [] }); }
});

// ── SOCKET.IO ─────────────────────────────────────────────────────────────────
class MultiMap {
  constructor(){ this._m=new Map(); }
  set(uid,sid){ if(!this._m.has(uid))this._m.set(uid,new Set()); this._m.get(uid).add(sid); }
  get(uid){ return this._m.get(uid)?.values().next().value||null; }
  getAll(uid){ return[...(this._m.get(uid)||[])]; }
  delete(uid,sid){ this._m.get(uid)?.delete(sid); if(this._m.get(uid)?.size===0)this._m.delete(uid); }
  has(uid){ return this._m.has(uid)&&this._m.get(uid).size>0; }
}
const onlineMap = new MultiMap();

io.use((socket,next)=>{
  try{ socket.user=jwt.verify(socket.handshake.auth.token,JWT_SECRET); next(); }
  catch{ next(new Error('Unauthorised')); }
});

io.on('connection',(socket)=>{
  const uid=socket.user.id;
  onlineMap.set(uid,socket.id);
  db.prepare('UPDATE users SET online=1,last_seen=? WHERE id=?').run(Date.now(),uid);
  broadcastPresence(uid,true);
  socket.on('typing_start',({convId})=>{ const others=db.prepare('SELECT user_id FROM members WHERE conv_id=? AND user_id!=?').all(convId,uid); others.forEach(o=>onlineMap.getAll(o.user_id).forEach(sid=>io.to(sid).emit('typing_start',{convId}))); });
  socket.on('typing_stop', ({convId})=>{ const others=db.prepare('SELECT user_id FROM members WHERE conv_id=? AND user_id!=?').all(convId,uid); others.forEach(o=>onlineMap.getAll(o.user_id).forEach(sid=>io.to(sid).emit('typing_stop', {convId}))); });
  socket.on('disconnect',()=>{
    onlineMap.delete(uid,socket.id);
    if(!onlineMap.has(uid)){ db.prepare('UPDATE users SET online=0,last_seen=? WHERE id=?').run(Date.now(),uid); broadcastPresence(uid,false); }
  });
});

function broadcastPresence(uid,online){
  const contacts=db.prepare('SELECT DISTINCT m2.user_id FROM members m1 JOIN members m2 ON m2.conv_id=m1.conv_id AND m2.user_id!=m1.user_id WHERE m1.user_id=?').all(uid);
  contacts.forEach(c=>onlineMap.getAll(c.user_id).forEach(sid=>io.to(sid).emit('presence',{userId:uid,online})));
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
function publicUser(u){ return{id:u.id,username:u.username,name:u.name,online:!!u.online,last_seen:u.last_seen}; }
function fmtConv(r){
  return {
    id:r.id, is_group:!!r.is_group, name:r.is_group?r.grp_name:null, unread:r.unread,
    other:r.is_group?null:{id:r.ou_id,username:r.ou_username,name:r.ou_name,online:!!r.ou_online,last_seen:r.ou_last_seen},
    last_msg:r.last_type==='gif'?'🎞️ GIF':r.last_type==='sticker'?'🎭 Sticker':r.last_type==='image'?'🖼️ Image':(r.last_msg||''),
    last_at:r.last_at
  };
}

server.listen(PORT,()=>console.log(`\n⚡ Zappo running → http://localhost:${PORT}\n`));
