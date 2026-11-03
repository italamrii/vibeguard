export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ['high', 'medium', 'low'] as const;
export type Confidence = (typeof CONFIDENCES)[number];

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const CONFIDENCE_RANK: Readonly<Record<Confidence, number>> = {
  high: 3,
  medium: 2,
  low: 1,
};

export function severityRank(s: Severity): number {
  return SEVERITY_RANK[s];
}

export function confidenceRank(c: Confidence): number {
  return CONFIDENCE_RANK[c];
}

/** True when `s` is at least as severe as `threshold`. */
export function meetsSeverity(s: Severity, threshold: Severity): boolean {
  return SEVERITY_RANK[s] >= SEVERITY_RANK[threshold];
}

export function meetsConfidence(c: Confidence, threshold: Confidence): boolean {
  return CONFIDENCE_RANK[c] >= CONFIDENCE_RANK[threshold];
}

export function isSeverity(v: unknown): v is Severity {
  return typeof v === 'string' && (SEVERITIES as readonly string[]).includes(v);
}

export function isConfidence(v: unknown): v is Confidence {
  return typeof v === 'string' && (CONFIDENCES as readonly string[]).includes(v);
}
