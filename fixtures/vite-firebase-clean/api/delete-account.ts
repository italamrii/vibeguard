import admin from 'firebase-admin';
import type { VercelRequest, VercelResponse } from '@vercel/node';

if (!admin.apps.length) admin.initializeApp();

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const token = String(req.headers.authorization ?? '').replace('Bearer ', '');
  const decoded = await admin.auth().verifyIdToken(token);
  await admin.firestore().collection('users').doc(decoded.uid).delete();
  res.status(204).end();
}
