const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const db = new Database(path.join(__dirname, 'app.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function createToken(user) {
  return jwt.sign({ sub: user.id, username: user.username, email: user.email }, JWT_SECRET, {
    expiresIn: '1h'
  });
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing Bearer token.' });
  }

  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'username, email, and password are required.' });
  }

  const existing = db
    .prepare('SELECT id FROM users WHERE username = ? OR email = ?')
    .get(username, email);

  if (existing) {
    return res.status(409).json({ error: 'Username or email already exists.' });
  }

  const salt = await bcrypt.genSalt(10);
  const passwordHash = await bcrypt.hash(password, salt);

  const result = db
    .prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)')
    .run(username, email, passwordHash);

  const user = { id: result.lastInsertRowid, username, email };
  const token = createToken(user);
  return res.status(201).json({ message: 'Account created.', token, user });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required.' });
  }

  const user = db
    .prepare('SELECT id, username, email, password_hash FROM users WHERE username = ?')
    .get(username);

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  const passwordOk = await bcrypt.compare(password, user.password_hash);
  if (!passwordOk) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  const token = createToken(user);
  return res.json({
    message: 'Login successful.',
    token,
    user: { id: user.id, username: user.username, email: user.email }
  });
});

app.get('/api/protected/profile', requireAuth, (req, res) => {
  const currentUser = db
    .prepare('SELECT id, username, email, created_at FROM users WHERE id = ?')
    .get(req.user.sub);

  if (!currentUser) {
    return res.status(404).json({ error: 'User not found.' });
  }

  return res.json({
    message: 'Protected profile retrieved successfully.',
    user: currentUser
  });
});

app.get('/api/protected/users', requireAuth, (req, res) => {
  const users = db.prepare('SELECT id, username, email, created_at FROM users ORDER BY id ASC').all();
  return res.json({ users });
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
