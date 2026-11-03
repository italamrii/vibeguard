// Cloudflare D1 binding (Next.js on Cloudflare via OpenNext).
import { getCloudflareContext } from '@opennextjs/cloudflare';

export function getD1() {
  return getCloudflareContext().env.DB;
}
