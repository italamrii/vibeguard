import { Resend } from 'resend';

// vg-expect: secrets/provider-key
export const resend = new Resend('{{FAKE:resend:mail}}');
