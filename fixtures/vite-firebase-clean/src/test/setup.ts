import { vi } from 'vitest';

vi.mock('firebase/app', () => ({
  initializeApp: () => ({ options: { apiKey: 'test-api-key', projectId: 'demo-test' } }),
}));
