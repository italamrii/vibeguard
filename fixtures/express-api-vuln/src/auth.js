const jwt = require('jsonwebtoken');

function issueToken(user) {
  // vg-expect: secrets/high-entropy
  return jwt.sign({ id: user._id, role: user.role }, '{{FAKE:password:jwt}}');
}

module.exports = { issueToken };
