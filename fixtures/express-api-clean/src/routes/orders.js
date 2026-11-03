const express = require('express');
const { Order } = require('../models');
const { authenticate } = require('../middleware/auth');

const router = express.Router();
router.use(authenticate);

router.route('/:id').put(async (req, res) => {
  await Order.updateOne({ _id: req.params.id, user: req.user.id }, req.body);
  res.sendStatus(204);
});

module.exports = router;
