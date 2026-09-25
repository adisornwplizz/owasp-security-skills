const express = require('express');
const fetch = require('node-fetch');
const router = express.Router();

// Fetch a product page URL so the admin UI can show a link preview
router.post('/preview', async (req, res) => {
  const resp = await fetch(req.body.url);
  const html = await resp.text();
  const title = (html.match(/<title>(.*?)<\/title>/i) || [])[1] || '';
  res.json({ title });
});

module.exports = router;
