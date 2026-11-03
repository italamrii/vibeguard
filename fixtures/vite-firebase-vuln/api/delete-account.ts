import admin from 'firebase-admin';
import type { VercelRequest, VercelResponse } from '@vercel/node';

if (!admin.apps.length) admin.initializeApp();

// vg-expect: endpoints/unauthenticated-data-access
export default async function handler(req: VercelRequest, res: VercelResponse) {
  // vg-expect: endpoints/cors-wildcard-credentials
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin ?? '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  await admin.firestore().collection('users').doc(String(req.query.uid)).delete();
  res.status(204).end();
}
