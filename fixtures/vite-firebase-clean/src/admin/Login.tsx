import { signInWithEmailAndPassword } from 'firebase/auth';
import { useState } from 'react';
import { auth } from '../firebase';

export function AdminLogin() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const passwordLabel = 'Password';
  const recaptchaSiteKey = import.meta.env.VITE_RECAPTCHA_SITE_KEY;
  return (
    <form data-sitekey={recaptchaSiteKey} onSubmit={() => signInWithEmailAndPassword(auth, email, password)}>
      <input value={email} onChange={(e) => setEmail(e.target.value)} />
      <input aria-label={passwordLabel} type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
    </form>
  );
}
