const mongoose = require('mongoose');

async function connect() {
  // vg-expect: secrets/provider-key
  await mongoose.connect('mongodb+srv://admin:{{FAKE:db_password:mongo2}}@cluster0.{{FAKE:supabase_ref:mongo}}.mongodb.net/app');
}

module.exports = { connect };
