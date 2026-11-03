const mongoose = require('mongoose');

const User = mongoose.model('User', new mongoose.Schema({ email: String, name: String, passwordHash: String }));
const Order = mongoose.model('Order', new mongoose.Schema({ user: String, status: String }));

module.exports = { User, Order };
