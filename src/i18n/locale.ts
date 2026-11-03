export const LOCALES = ['en', 'ar'] as const;
export type Locale = (typeof LOCALES)[number];

/**
 * A value provided in every supported locale. Because this is a total Record, adding a
 * locale or forgetting a translation is a compile error, not a runtime fallback.
 */
export type Localized<T = string> = Readonly<Record<Locale, T>>;

export function isLocale(v: unknown): v is Locale {
  return typeof v === 'string' && (LOCALES as readonly string[]).includes(v);
}

export function isRtl(locale: Locale): boolean {
  return locale === 'ar';
}

export type MessageParams = Readonly<Record<string, string | number>>;

/**
 * Replace `{name}` placeholders. Unknown placeholders are left verbatim so a missing
 * param is visible in output and caught by tests, rather than silently dropped.
 * `wrap` lets reporters escape or bidi-isolate interpolated values.
 */
export function interpolate(
  template: string,
  params: MessageParams,
  wrap: (value: string) => string = (v) => v,
): string {
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (whole, key: string) => {
    const v = params[key];
    return v === undefined ? whole : wrap(String(v));
  });
}
