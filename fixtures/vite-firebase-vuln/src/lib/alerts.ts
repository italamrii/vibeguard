// vg-expect: secrets/provider-key
const SLACK_WEBHOOK = '{{FAKE:slack_webhook:alerts}}';

export async function alert(text: string) {
  await fetch(SLACK_WEBHOOK, { method: 'POST', body: JSON.stringify({ text }) });
}
