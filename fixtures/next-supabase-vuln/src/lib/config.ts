export const config = {
  appName: 'Acme Notes',
  // vg-expect: secrets/high-entropy
  webhookSecret: '{{FAKE:hex40:webhook}}',
  passwordMinLength: 12,
};

// vg-expect: secrets/high-entropy
export const ADMIN_PASSWORD = '{{FAKE:password:admin}}';
