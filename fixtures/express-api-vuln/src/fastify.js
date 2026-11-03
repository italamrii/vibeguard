const Fastify = require('fastify');
const { db } = require('./db/drizzle');
const { notes } = require('./db/schema');

const fastify = Fastify();
fastify.register(require('@fastify/jwt'), { secret: process.env.JWT_SECRET });
fastify.decorate('authenticate', async (request) => request.jwtVerify());

// vg-expect: endpoints/unauthenticated-data-access
fastify.post('/api/notes', async (request) => {
  return db.insert(notes).values(request.body).returning();
});

fastify.get('/api/notes', { preHandler: [fastify.authenticate] }, async () => db.select().from(notes));

module.exports = fastify;
