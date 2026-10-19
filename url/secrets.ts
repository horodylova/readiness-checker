import type { Severity } from "../types";

export type SecretPattern = {
  id: string;
  name: string;
  regex: RegExp;
  severity: Severity;
  remedy: string;
  validate?: (match: string) => boolean;
};

export type SecretHit = { pattern: SecretPattern; value: string; source: string };

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const json = typeof atob === "function" ? atob(padded) : Buffer.from(padded, "base64").toString("binary");
    const data = JSON.parse(json);
    return data && typeof data === "object" ? (data as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

const rotate = "Rotate the key in the provider dashboard now, then move every call that needs it to a server route or edge function.";

export const secretPatterns: SecretPattern[] = [
  {
    id: "SEC-SUPA-SERVICE",
    name: "Supabase service role key",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g,
    severity: "critical",
    remedy: "Rotate the JWT secret in Supabase (Project Settings, JWT Keys) and keep the service role key on the server only. It bypasses every RLS policy.",
    validate: (m) => decodeJwtPayload(m)?.role === "service_role",
  },
  {
    id: "SEC-SUPA-SECRET",
    name: "Supabase secret key",
    regex: /\bsb_secret_[A-Za-z0-9_-]{20,}/g,
    severity: "critical",
    remedy: "Delete the secret key in Supabase (Project Settings, API Keys) and create a new one for the server.",
  },
  {
    id: "SEC-STRIPE-LIVE",
    name: "Stripe or Clerk live secret key",
    regex: /\bsk_live_[A-Za-z0-9]{24,}/g,
    severity: "critical",
    remedy: "Roll the key in the provider dashboard (Stripe: Developers, API keys; Clerk: API keys). Anyone holding a Stripe key can issue refunds and read customers; a Clerk key can read and change every user.",
  },
  {
    id: "SEC-STRIPE-RESTRICTED",
    name: "Stripe restricted key",
    regex: /\brk_live_[A-Za-z0-9]{24,}/g,
    severity: "high",
    remedy: rotate,
  },
  {
    id: "SEC-STRIPE-TEST",
    name: "Stripe or Clerk test secret key",
    regex: /\bsk_test_[A-Za-z0-9]{24,}/g,
    severity: "medium",
    remedy: "Roll the test key and move it to the server. A test key in the bundle usually means the live key will end up there too.",
  },
  {
    id: "SEC-STRIPE-WEBHOOK",
    name: "Stripe webhook signing secret",
    regex: /\bwhsec_[A-Za-z0-9]{24,}/g,
    severity: "high",
    remedy: "Roll the signing secret for the endpoint. With it anyone can forge payment events your server will trust.",
  },
  {
    id: "SEC-OPENAI",
    name: "OpenAI API key",
    regex: /\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|\bsk-proj-[A-Za-z0-9_-]{80,}/g,
    severity: "critical",
    remedy: rotate,
  },
  {
    id: "SEC-ANTHROPIC",
    name: "Anthropic API key",
    regex: /\bsk-ant-(api|admin)\d{2}-[A-Za-z0-9_-]{80,}/g,
    severity: "critical",
    remedy: rotate,
  },
  {
    id: "SEC-GOOGLE-AI",
    name: "Google API key",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: "low",
    remedy: "If this is a Firebase or Maps browser key, restrict it in Google Cloud Console to your domains and to the APIs it needs. If it is a Gemini key, rotate it and move the calls to the server.",
  },
  {
    id: "SEC-AWS",
    name: "AWS access key ID",
    regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
    severity: "high",
    remedy: "Deactivate the key in IAM and check CloudTrail for use. Browser uploads should use presigned URLs from the server.",
  },
  {
    id: "SEC-GITHUB",
    name: "GitHub token",
    regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/g,
    severity: "critical",
    remedy: "Revoke the token in GitHub settings.",
  },
  {
    id: "SEC-RESEND",
    name: "Resend API key",
    regex: /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}/g,
    severity: "high",
    remedy: rotate,
  },
  {
    id: "SEC-SENDGRID",
    name: "SendGrid API key",
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    severity: "high",
    remedy: rotate,
  },
  {
    id: "SEC-TWILIO",
    name: "Twilio API key",
    regex: /(?<![\w-])SK[0-9a-f]{32}\b/g,
    severity: "high",
    remedy: rotate,
  },
  {
    id: "SEC-MAILGUN",
    name: "Mailgun API key",
    regex: /(?<![\w-])key-[0-9a-f]{32}\b/g,
    severity: "high",
    remedy: rotate,
  },
  {
    id: "SEC-SLACK",
    name: "Slack token",
    regex: /\bxox[baprs]-[0-9A-Za-z-]{20,}/g,
    severity: "high",
    remedy: "Revoke the token in the Slack app settings.",
  },
  {
    id: "SEC-SLACK-WEBHOOK",
    name: "Slack webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g,
    severity: "medium",
    remedy: "Regenerate the webhook in Slack. Anyone can post to your channel with it.",
  },
  {
    id: "SEC-PRIVATE-KEY",
    name: "Private key",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?:\\r|\\n|\s)*(?:[A-Za-z0-9+/=]|\\r|\\n|\s){100,}/g,
    severity: "critical",
    remedy: "Replace the key pair and remove the private key from the front end.",
  },
  {
    id: "SEC-DB-URL",
    name: "Database connection string with password",
    regex: /\b(postgres|postgresql|mysql|mongodb(\+srv)?):\/\/[A-Za-z0-9._%-]+:[^@\s"'`]{6,}@[A-Za-z0-9.-]+/g,
    severity: "critical",
    remedy: "Change the database password now. The front end must never connect to the database directly.",
    validate: (m) => !/:(password|pass|\*+|<[^>]*>|\$\{)/i.test(m),
  },
];

export function redact(value: string): string {
  if (value.startsWith("-----BEGIN")) {
    const header = value.match(/^-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/)?.[0] ?? value.slice(0, 32);
    return `${header}…`;
  }
  if (value.length <= 12) return `${value.slice(0, 3)}…`;
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

export function findSecrets(text: string, source: string): SecretHit[] {
  const hits: SecretHit[] = [];
  const seen = new Set<string>();
  for (const pattern of secretPatterns) {
    pattern.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.regex.exec(text))) {
      const value = m[0];
      if (pattern.validate && !pattern.validate(value)) continue;
      const key = `${pattern.id}:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ pattern, value, source });
    }
  }
  return hits;
}
