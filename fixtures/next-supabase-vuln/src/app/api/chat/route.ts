import OpenAI from 'openai';

// vg-expect: secrets/provider-key
const openai = new OpenAI({ apiKey: '{{FAKE:openai_proj:main}}' });

// Anyone can spend the OpenAI quota through this endpoint.
// vg-expect: endpoints/unauthenticated-data-access
export async function POST(req: Request) {
  const { message } = (await req.json()) as { message: string };
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: message }],
  });
  return Response.json(completion.choices[0]?.message);
}
