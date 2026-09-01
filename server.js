// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const Redis = require('ioredis');
const Database = require('better-sqlite3');

const app = express();
app.use(express.json());

const redis = new Redis({ host: '127.0.0.1', port: 6379 });
const db = new Database('database.sqlite');

// Auto-create the table (replacing TypeORM's synchronize)
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usernameHash TEXT UNIQUE,
    passwordHash TEXT,
    steamId TEXT UNIQUE,
    lastIpHash TEXT
  )
`);

const hashData = (data) => crypto.createHash('sha256').update(data).digest('hex');

// Prepared statements for safe, injection-free queries
const insertUser = db.prepare('INSERT INTO users (usernameHash, passwordHash, lastIpHash) VALUES (?, ?, ?)');
const updateSteamId = db.prepare('UPDATE users SET steamId = ? WHERE id = ?');
const findUser = db.prepare('SELECT * FROM users WHERE usernameHash = ?');
const updateIp = db.prepare('UPDATE users SET lastIpHash = ? WHERE id = ?');

app.post('/auth/register', async (req, res) => {
  try {
    const cleanIp = req.ip.replace('::ffff:', '');
    const usernameHash = hashData(req.body.username);
    
    if (findUser.get(usernameHash)) {
      return res.status(409).json({ message: 'User already exists' });
    }

    const passwordHash = await bcrypt.hash(req.body.password, 10);
    const lastIpHash = hashData(cleanIp);

    const info = insertUser.run(usernameHash, passwordHash, lastIpHash);
    const steamId = `STEAM_0:1:${10000 + info.lastInsertRowid}`;
    
    updateSteamId.run(steamId, info.lastInsertRowid);

    res.json({ message: 'Registration successful', steamId });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const cleanIp = req.ip.replace('::ffff:', '');
    const user = findUser.get(hashData(req.body.username));

    if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    updateIp.run(hashData(cleanIp), user.id);
    await redis.set(`session:${cleanIp}`, user.steamId, 'EX', 300);

    res.json({ message: 'Login successful. You have 5 minutes to join the server.' });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/auth/heartbeat', async (req, res) => {
  const cleanIp = req.ip.replace('::ffff:', '');
  const exists = await redis.exists(`session:${cleanIp}`);
  
  if (exists) {
    await redis.expire(`session:${cleanIp}`, 300);
    return res.json({ message: 'Connection extended' });
  }
  res.status(401).json({ message: 'Session expired' });
});

app.listen(3000, () => console.log('Express Auth Server running on port 3000'));