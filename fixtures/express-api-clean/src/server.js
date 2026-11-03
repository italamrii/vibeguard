const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { User } = require('./models');
const { authenticate } = require('./middleware/auth');
const { issueToken } = require('./auth');

const app = express();
app.use(express.json());
const allowedOrigins = ['https://app.acme.example'];
app.use(cors({ origin: allowedOrigins, credentials: true }));

const guard = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5 });

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/login', guard, async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) return res.sendStatus(401);
  res.json({ token: issueToken(user) });
});

// Everything registered below requires a valid token.
app.use(authenticate);

app.get('/api/users', async (req, res) => {
  res.json(await User.find({}, 'email name'));
});

app.delete('/api/users/:id', async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.sendStatus(204);
});

app.use('/api/orders', require('./routes/orders'));

module.exports = app;
