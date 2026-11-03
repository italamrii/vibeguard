import { useState } from 'react';

export function AdminLogin({ onOk }: { onOk: () => void }) {
  const [password, setPassword] = useState('');
  function submit() {
    // vg-expect: secrets/client-exposed-env
    if (password === import.meta.env.VITE_ADMIN_PASSWORD) onOk();
  }
  return <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} onBlur={submit} />;
}
