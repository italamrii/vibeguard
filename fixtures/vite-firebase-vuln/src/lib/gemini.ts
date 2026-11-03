import { GoogleGenerativeAI } from '@google/generative-ai';

// vg-expect: secrets/provider-key
const genAI = new GoogleGenerativeAI('{{FAKE:google_api:gemini}}');

export const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
