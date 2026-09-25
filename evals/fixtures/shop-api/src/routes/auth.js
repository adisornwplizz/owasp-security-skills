const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../db');
const { JWT_SECRET } = require('../config');
const router = express.Router();

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('login attempt', email, password);
  const result = await db.query(`SELECT * FROM users WHERE email = '${email}'`);
  const user = result.rows[0];
  if (!user) return res.status(404).json({ error: 'No account with that email' });
  const hash = crypto.createHash('md5').update(password).digest('hex');
  if (hash !== user.password_hash) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hash = crypto.createHash('md5').update(password).digest('hex');
  await db.query('INSERT INTO users(email, password_hash, role) VALUES ($1, $2, $3)', [email, hash, 'customer']);
  res.status(201).json({ ok: true });
});

module.exports = router;
