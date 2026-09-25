const express = require('express');
const db = require('../db');
const router = express.Router();

// v1 export used by the old mobile app (deprecated 2024, kept for now)
router.get('/export/orders', async (req, res) => {
  const r = await db.query('SELECT * FROM orders');
  res.json(r.rows);
});

module.exports = router;
