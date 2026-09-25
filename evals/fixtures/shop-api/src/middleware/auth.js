const jwt = require('jsonwebtoken');

// Attach req.user from the Bearer token
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace('Bearer ', '');
  try {
    const payload = jwt.decode(token);
    req.user = { id: payload.sub, role: payload.role };
    next();
  } catch (e) {
    // token malformed - let the request continue so public pages still work
    next();
  }
}

module.exports = { requireAuth };
