const express = require('express');
const helmet = require('helmet');
const pino = require('pino-http');
const rateLimit = require('express-rate-limit');
const { requireAuth } = require('./middleware/auth');

const app = express();
app.use(helmet());
app.use(pino());
app.use(express.json({ limit: '100kb' }));
app.use(rateLimit({ windowMs: 60_000, limit: 300 }));

app.get('/healthz', (req, res) => res.json({ ok: true }));

app.use(requireAuth);
app.use('/invoices', require('./routes/invoices'));

app.use((err, req, res, next) => {
  req.log.error(err);
  res.status(500).json({ error: 'internal error' });
});

module.exports = app;
