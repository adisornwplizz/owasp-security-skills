const express = require('express');
const _ = require('lodash');
const db = require('../db');
const router = express.Router();

router.get('/me', async (req, res) => {
  const r = await db.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  res.json(r.rows[0]); // includes password_hash, role, reset_token
});

router.put('/me', async (req, res) => {
  const current = (await db.query('SELECT * FROM users WHERE id = $1', [req.user.id])).rows[0];
  const updated = _.merge(current, req.body);
  await db.query(
    'UPDATE users SET email=$1, name=$2, role=$3 WHERE id=$4',
    [updated.email, updated.name, updated.role, req.user.id]
  );
  res.json(updated);
});

// admin: list all users
router.get('/admin/all', async (req, res) => {
  const r = await db.query('SELECT id, email, role, created_at FROM users');
  res.json(r.rows);
});

module.exports = router;
