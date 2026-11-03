const mongoose = require('mongoose');

async function connect() {
  const uri = process.env.MONGODB_URI ?? 'mongodb://localhost:27017/app';
  await mongoose.connect(uri);
}

module.exports = { connect };
