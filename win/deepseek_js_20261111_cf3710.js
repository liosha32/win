const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const ADMIN_PASS = '22118899BNA22118899BNA';
const DATA = path.join(__dirname, 'data.json');

let db = { accounts: {}, sessions: {}, admins: {} };
try {
  db = JSON.parse(fs.readFileSync(DATA, 'utf8'));
  db.sessions = {}; db.admins = {}; // инвалидация при рестарте
} catch (e) { db = { accounts: {}, sessions: {}, admins: {} }; }
function persist() { fs.writeFileSync(DATA, JSON.stringify(db)); }

const app = express();
app.use(express.json({ limit: '2mb' }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const freshS = () => ({ bal: 1000, debt: 0, dp: .05, days: 1, admin: 0, bg: "Темный", bt: "Стандартный", pn: "Стандартный", owned: ["bg:Темный", "bt:Стандартный", "pn:Стандартный"], used: [], pred: 0, pr: null, tB: 0, tP: 0, tC: 0, tG: 0, skins: [] });
const hashPass = (pass, salt) => crypto.createHash('sha256').update(salt + ':' + pass).digest('hex');
const idFromNick = nick => crypto.createHash('sha256').update(nick.toLowerCase()).digest('hex').slice(0, 32);
const randToken = () => crypto.randomBytes(32).toString('hex');

function authUser(req) {
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!tok) return null;
  const s = db.sessions[tok]; if (!s) return null;
  const acc = db.accounts[s.id]; if (!acc || acc.banned) return null;
  return { token: tok, acc };
}
function authAdmin(req) {
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  return tok && db.admins[tok] ? tok : null;
}
function pub(acc) {
  return { id: acc.id, nick: acc.nick, bal: Math.round((acc.s && acc.s.bal) || 0), banned: acc.banned || 0, t: acc.t || 0 };
}
function killSessions(id) {
  for (const [t, s] of Object.entries(db.sessions)) if (s.id === id) delete db.sessions[t];
}

app.post('/api/register', (req, res) => {
  const { nick, pass } = req.body || {};
  if (typeof nick !== 'string' || typeof pass !== 'string') return res.status(400).json({ error: 'bad input' });
  if (!/^[\p{L}\p{N}_\- ]{2,16}$/u.test(nick)) return res.status(400).json({ error: 'Ник: 2–16 символов, буквы и цифры' });
  if (pass.length < 3 || pass.length > 24) return res.status(400).json({ error: 'Пароль: 3–24 символа' });
  const id = idFromNick(nick);
  if (db.accounts[id]) return res.status(400).json({ error: 'Этот ник уже занят' });
  const salt = randToken(), token = randToken();
  const acc = { id, nick, salt, passHash: hashPass(pass, salt), banned: 0, t: Date.now(), s: freshS(), lastAckBal: 1000 };
  db.accounts[id] = acc;
  db.sessions[token] = { id };
  persist();
  res.json({ token, me: { id, nick: acc.nick, bal: acc.s.bal, s: acc.s } });
});

app.post('/api/login', (req, res) => {
  const { nick, pass } = req.body || {};
  if (typeof nick !== 'string' || typeof pass !== 'string') return res.status(400).json({ error: 'bad input' });
  const id = idFromNick(nick);
  const acc = db.accounts[id];
  if (!acc) return res.status(400).json({ error: 'Неверный ник или пароль' });
  if (acc.banned) return res.status(400).json({ error: 'Аккаунт заблокирован' });
  if (hashPass(pass, acc.salt) !== acc.passHash) return res.status(400).json({ error: 'Неверный ник или пароль' });
  const token = randToken();
  db.sessions[token] = { id };
  acc.lastAckBal = acc.s.bal;
  persist();
  res.json({ token, me: { id, nick: acc.nick, bal: acc.s.bal, s: acc.s } });
});

app.post('/api/logout', (req, res) => {
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (tok && db.sessions[tok]) { delete db.sessions[tok]; persist(); }
  res.json({});
});

app.get('/api/me', (req, res) => {
  const u = authUser(req);
  if (!u) return res.status(401).json({ error: 'unauth' });
  res.json({ me: { id: u.acc.id, nick: u.acc.nick, bal: u.acc.s.bal, s: u.acc.s } });
});

app.put('/api/save', (req, res) => {
  const u = authUser(req);
  if (!u) return res.status(401).json({ error: 'unauth' });
  const s = req.body && req.body.s;
  if (!s || typeof s !== 'object') return res.status(400).json({ error: 'bad s' });
  const clientBal = typeof s.bal === 'number' ? s.bal : 0;
  const lastAck = typeof u.acc.lastAckBal === 'number' ? u.acc.lastAckBal : clientBal;
  const delta = Math.round(clientBal - lastAck);
  const serverBal = typeof u.acc.s.bal === 'number' ? u.acc.s.bal : 0;
  const newBal = Math.max(0, serverBal + delta);
  u.acc.s = s;
  u.acc.s.bal = newBal;
  u.acc.lastAckBal = newBal;
  u.acc.t = Date.now();
  persist();
  res.json({ bal: newBal });
});

app.post('/api/admin/login', (req, res) => {
  const { pass } = req.body || {};
  if (pass !== ADMIN_PASS) return res.status(400).json({ error: 'Неверный пароль' });
  const tok = randToken();
  db.admins[tok] = Date.now();
  persist();
  res.json({ adminToken: tok });
});

app.get('/api/admin/players', (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ error: 'unauth' });
  const list = Object.values(db.accounts).map(pub).sort((a, b) => b.t - a.t);
  res.json({ players: list });
});

app.get('/api/admin/get/:id', (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ error: 'unauth' });
  const acc = db.accounts[req.params.id];
  if (!acc) return res.status(404).json({ error: 'not found' });
  res.json({ account: pub(acc), s: acc.s });
});

app.post('/api/admin/update', (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ error: 'unauth' });
  const { targetId, amount, pass, banned, s, delete: del } = req.body || {};
  const acc = db.accounts[targetId];
  if (!acc) return res.status(404).json({ error: 'not found' });

  if (del) {
    delete db.accounts[targetId];
    killSessions(targetId);
    persist();
    return res.json({});
  }
  if (typeof amount === 'number' && amount !== 0) acc.s.bal = Math.max(0, (acc.s.bal || 0) + amount);
  if (typeof pass === 'string' && pass.length >= 3 && pass.length <= 24) {
    acc.salt = randToken();
    acc.passHash = hashPass(pass, acc.salt);
    killSessions(targetId);
  }
  if (typeof banned === 'number') {
    acc.banned = banned ? 1 : 0;
    if (acc.banned) killSessions(targetId);
  }
  if (s && typeof s === 'object') {
    const keepBal = acc.s.bal;
    acc.s = s;
    acc.s.bal = keepBal;
    acc.lastAckBal = keepBal;
  }
  acc.t = Date.now();
  persist();
  res.json({});
});

app.listen(PORT, () => console.log('Сервер: http://localhost:' + PORT));