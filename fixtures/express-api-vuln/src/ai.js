const Anthropic = require('@anthropic-ai/sdk');

// vg-expect: secrets/provider-key
const anthropic = new Anthropic({ apiKey: '{{FAKE:anthropic:main}}' });

module.exports = { anthropic };
