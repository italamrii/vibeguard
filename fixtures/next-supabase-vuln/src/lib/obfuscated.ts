// A key split across string concatenation is not reassembled by VibeGuard v1.
const prefix = 'sk' + '_live_';
// vg-expect-miss: secrets/provider-key -- concatenated secrets are not reassembled (threat model)
export const STRIPE_KEY = prefix + '{{FAKE:b62_99:split}}';
