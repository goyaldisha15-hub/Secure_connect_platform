const jwt = require('jsonwebtoken');

// Cookie header se "token" nikalta hai (cookie-parser ki zaroorat nahi)
function tokenFromCookie(req) {
  const raw = req.headers.cookie;
  if (!raw) return null;
  const pair = raw.split(';').map((c) => c.trim()).find((c) => c.startsWith('token='));
  return pair ? decodeURIComponent(pair.slice(6)) : null;
}

function extractToken(req) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) return header.slice(7);
  return tokenFromCookie(req);
}

function authenticate(req, res, next) {
  const token = extractToken(req);
  if (!token) return res.status(403).json({ message: 'No token provided' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET); // { id, username, role }
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// RBAC: sirf diye gaye roles allowed
const authorizeRoles = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ message: 'Access denied' });
  }
  next();
};

module.exports = { authenticate, authorizeRoles };