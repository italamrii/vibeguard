'use client';
import { useState } from 'react';

export function AiWidget() {
  const [answer, setAnswer] = useState('');

  async function ask(question: string) {
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        // vg-expect: secrets/client-exposed-env
        Authorization: `Bearer ${process.env.NEXT_PUBLIC_OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: question }] }),
    });
    setAnswer(JSON.stringify(await res.json()));
  }

  return <button onClick={() => ask('Summarise my notes')}>{answer || 'Ask AI'}</button>;
}
