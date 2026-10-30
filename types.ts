export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const severityOrder: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export type Finding = {
  rule: string;
  severity: Severity;
  object: string;
  title: string;
  detail: string;
  remedy?: string;
  evidence?: string;
};

export type Engine = "supabase-inventory" | "url" | "stripe-endpoints" | "stripe-signature" | "stripe-code";

export type DetectedStack = {
  supabase?: { url?: string; projectRef?: string; anonKeyFound: boolean };
  firebase?: { projectId?: string };
  stripe?: { publishableKeyFound: boolean };
  frameworks: string[];
};

export type Report = {
  engine: Engine;
  findings: Finding[];
  summary: Record<Severity, number>;
  notChecked: string[];
  stack?: DetectedStack;
  next?: string[];
  warnings: string[];
};

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      severityOrder[a.severity] - severityOrder[b.severity] ||
      a.object.localeCompare(b.object) ||
      a.rule.localeCompare(b.rule),
  );
}

export function summarise(findings: Finding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity] += 1;
  return out;
}
