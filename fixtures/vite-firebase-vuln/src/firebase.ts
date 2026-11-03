import { initializeApp } from 'firebase/app';
import { getAuth } from 'firebase/auth';

// Firebase web config is public by design; Security Rules protect the data.
const firebaseConfig = {
  apiKey: '{{FAKE:google_api:firebase}}',
  authDomain: 'acme-tasks-fake.firebaseapp.com',
  projectId: 'acme-tasks-fake',
  appId: '1:000000000000:web:{{FAKE:hex40:appid}}',
};

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
