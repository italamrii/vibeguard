const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { User } = require('./models');
const { requireAuth } = require('./middleware/auth');
const { issueToken } = require('./auth');

const app = express();
app.use(express.json());
// vg-expect: endpoints/cors-wildcard-credentials
app.use(cors({ origin: true, credentials: true }));

app.get('/api/health', (req, res) => res.json({ ok: true }));

// vg-expect: endpoints/unauthenticated-data-access
app.get('/api/users', async (req, res) => {
  res.json(await User.find({}, 'email name'));
});

// vg-expect: endpoints/unauthenticated-data-access
app.delete('/api/users/:id', async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.sendStatus(204);
});

app.get('/api/me', requireAuth, async (req, res) => {
  res.json(await User.findById(req.user.id));
});

// vg-expect: endpoints/auth-route-no-rate-limit
app.post('/api/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password, user.passwordHash))) return res.sendStatus(401);
  res.json({ token: issueToken(user) });
});

// vg-expect: endpoints/auth-route-no-rate-limit
app.post('/api/reset-password', async (req, res) => {
  await User.updateOne({ email: req.body.email }, { resetToken: Math.random().toString(36) });
  res.sendStatus(202);
});

app.use('/api/orders', require('./routes/orders'));

module.exports = app;
