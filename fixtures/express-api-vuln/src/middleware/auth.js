const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  try {
    req.user = jwt.verify(String(req.headers.authorization).replace('Bearer ', ''), process.env.JWT_SECRET);
    next();
  } catch {
    res.sendStatus(401);
  }
}

module.exports = { requireAuth };
