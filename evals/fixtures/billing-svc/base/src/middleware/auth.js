const { jwtVerify, createRemoteJWKSet } = require('jose');
const JWKS = createRemoteJWKSet(new URL(process.env.AUTH_JWKS_URL));

async function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: process.env.AUTH_ISSUER,
      audience: 'billing-svc',
      algorithms: ['RS256'],
    });
    req.user = { id: payload.sub, orgId: payload.org_id, role: payload.role };
    return next();
  } catch (e) {
    req.log.warn({ err: e.code }, 'auth failed');
    return res.status(401).json({ error: 'unauthorized' });
  }
}
module.exports = { requireAuth };
