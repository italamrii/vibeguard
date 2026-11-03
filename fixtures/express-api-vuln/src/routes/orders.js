const express = require('express');
const { Order } = require('../models');

const router = express.Router();

// vg-expect: endpoints/unauthenticated-data-access
router.route('/:id').put(async (req, res) => {
  await Order.updateOne({ _id: req.params.id }, req.body);
  res.sendStatus(204);
});

module.exports = router;
