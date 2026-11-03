const session = require('express-session');

// The "dev fallback" that ships to production when the env var is missing.
// vg-expect: secrets/high-entropy
const SESSION_SECRET = process.env.SESSION_SECRET || '{{FAKE:b64_48:sessfallback}}';

module.exports = session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false });
