const express = require('express');
const cors = require('cors');
const path = require('path');
const { PORT } = require('./config');
const { requireAuth } = require('./middleware/auth');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use('/api/v1', require('./routes/legacy'));
app.use('/api/auth', require('./routes/auth'));
app.use('/api/orders', requireAuth, require('./routes/orders'));
app.use('/api/users', requireAuth, require('./routes/users'));
app.use('/api/tools', requireAuth, require('./routes/tools'));

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

app.listen(PORT, () => console.log(`shop-api listening on ${PORT}`));
