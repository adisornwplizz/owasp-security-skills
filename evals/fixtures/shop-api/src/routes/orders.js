const express = require('express');
const db = require('../db');
const router = express.Router();

// list my orders
router.get('/', async (req, res) => {
  const limit = req.query.limit || 20;
  const r = await db.query('SELECT * FROM orders WHERE user_id = $1 LIMIT ' + limit, [req.user.id]);
  res.json(r.rows);
});

// order detail
router.get('/:id', async (req, res) => {
  const r = await db.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
  if (!r.rows[0]) return res.status(404).end();
  res.json(r.rows[0]);
});

// checkout
router.post('/checkout', async (req, res) => {
  const { productId, quantity, price } = req.body;
  const total = price * quantity;
  const r = await db.query(
    'INSERT INTO orders(user_id, product_id, quantity, total) VALUES ($1,$2,$3,$4) RETURNING *',
    [req.user.id, productId, quantity, total]
  );
  res.status(201).json(r.rows[0]);
});

module.exports = router;
