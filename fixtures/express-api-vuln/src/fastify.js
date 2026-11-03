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

// Encapsulation: the hook registered inside this plugin protects only the plugin's routes.
fastify.register(async function adminPlugin(fastify) {
  fastify.addHook('onRequest', fastify.authenticate);
  fastify.get('/api/admin/notes', async () => db.select().from(notes));
});

// Outside the plugin: not protected by its onRequest hook.
// vg-expect: endpoints/unauthenticated-data-access
fastify.delete('/api/notes/:id', async (request) => db.delete(notes).where(eq(notes.id, request.params.id)));

module.exports = fastify;
