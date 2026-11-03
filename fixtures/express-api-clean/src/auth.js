const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be set');

function issueToken(user) {
  return jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
}

const passwordPolicy = { minLength: 12, requireDigit: true };
const tokenHeaderName = 'authorization';

module.exports = { issueToken, passwordPolicy, tokenHeaderName };
