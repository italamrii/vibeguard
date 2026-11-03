import type { Endpoint } from '../../analysis/routes.ts';
import type { RuleContext } from '../../core/engine/rule.ts';
import { findMiddleware, middlewareCovers, type MiddlewareInfo } from './next-middleware.ts';
import { SignalAnalyzer } from './signals.ts';

export const ENDPOINT_REFERENCES = [
  'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/',
  'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
  'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html',
] as const;

/** Credential endpoints: public by necessity, so they need rate limiting instead of auth. */
const AUTH_LIKE_PATH =
  /(?:^|\/)(?:login|log-in|signin|sign-in|signup|sign-up|register|forgot-password|reset-password|password-reset|password|otp|verify-otp|verify-code|magic-link|token|2fa|mfa)(?:\/|$)/i;
const AUTH_LIKE_ACTION =
  /^(?:log_?in|sign_?in|sign_?up|register|reset\w*password|forgot\w*|request\w*reset|verify\w*(?:otp|code)|send\w*(?:otp|code|magic\w*))/i;
/** Library-owned auth handlers (NextAuth, better-auth, …) and non-credential auth routes. */
const LIBRARY_OR_NON_CREDENTIAL =
  /\[\.\.\.|callback|logout|log-out|signout|sign-out|session|refresh(?:$|\/)/i;

export function isAuthLike(ep: Endpoint): boolean {
  if (ep.kind === 'server-action') return AUTH_LIKE_ACTION.test(ep.path);
  if (LIBRARY_OR_NON_CREDENTIAL.test(ep.path)) return false;
  return AUTH_LIKE_PATH.test(ep.path);
}

/** Endpoints that are public by design and normally touch no user data. */
export function isPublicUtility(ep: Endpoint): boolean {
  return /(?:^|\/)(?:health|healthz|status|ping|ready|live|version|og|sitemap(?:\.xml)?|robots(?:\.txt)?|manifest)(?:\/|$)/i.test(
    ep.path,
  );
}

/**
 * Logout / sign-out endpoints act on the caller's own session (taken from its cookie or
 * token) and are public by design: there is nothing to authenticate before ending a session.
 */
export function isSessionTermination(ep: Endpoint): boolean {
  if (ep.kind === 'server-action') return /^(?:log_?out|sign_?out)/i.test(ep.path);
  return /(?:^|\/)(?:logout|log-out|signout|sign-out)(?:\/|$)/i.test(ep.path);
}

export function describe(ep: Endpoint): string {
  return ep.kind === 'server-action' ? `server action ${ep.path}()` : `${ep.method} ${ep.path}`;
}

export interface EndpointContext {
  readonly signals: SignalAnalyzer;
  readonly middleware: readonly MiddlewareInfo[];
}

const cache = new WeakMap<RuleContext, Promise<EndpointContext>>();

export function endpointContext(ctx: RuleContext): Promise<EndpointContext> {
  let p = cache.get(ctx);
  if (!p) {
    p = (async () => {
      const signals = new SignalAnalyzer(ctx);
      return { signals, middleware: await findMiddleware(ctx, signals) };
    })();
    cache.set(ctx, p);
  }
  return p;
}

/** Next.js middleware/proxy that covers this endpoint and satisfies `pred`. */
export function coveredByMiddleware(
  ec: EndpointContext,
  ep: Endpoint,
  pred: (m: MiddlewareInfo) => boolean,
): boolean {
  if (ep.kind !== 'next-route' && ep.kind !== 'next-pages-api') return false;
  return ec.middleware.some((m) => pred(m) && middlewareCovers(m, ep.file, ep.path));
}
