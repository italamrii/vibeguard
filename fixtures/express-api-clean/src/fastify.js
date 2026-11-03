const Fastify = require('fastify');
const { db } = require('./db/drizzle');
const { notes } = require('./db/schema');

const fastify = Fastify();
fastify.register(require('@fastify/jwt'), { secret: process.env.JWT_SECRET });
fastify.register(require('@fastify/rate-limit'), { max: 100, timeWindow: '1 minute' });
fastify.decorate('authenticate', async (request) => request.jwtVerify());
fastify.addHook('onRequest', fastify.authenticate);

fastify.post('/api/notes', async (request) => {
  return db.insert(notes).values({ ...request.body, owner: request.user.sub }).returning();
});

module.exports = fastify;
