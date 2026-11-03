const allowed = ['https://app.acme.example', 'https://admin.acme.example'];

// Echoes the origin only after checking it against the allowlist.
module.exports = function legacyCors(req, res, next) {
  const origin = req.headers.origin;
  if (allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
};
