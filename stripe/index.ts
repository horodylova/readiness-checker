import type { Report } from "../types";
import { codeReport, detectStripeCode } from "./code";
import { endpointsReport, parseEndpoints } from "./endpoints";
import { probeCommand, signatureReport } from "./signature";

export type StripeInput =
  | { kind: "endpoints" }
  | { kind: "signature" }
  | { kind: "code" }
  | { kind: "unknown"; message: string };

const ACCEPTED =
  "The check accepts three kinds of input: the JSON from the webhook endpoints command, the output of the signature test command, or the webhook handler and checkout code.";

export function detectStripeInput(raw: string): StripeInput {
  const s = raw.trim();
  if (!s) return { kind: "unknown", message: ACCEPTED };
  if (/^(curl(\.exe)?\s+-|stripe\s+webhook_endpoints\b)/m.test(s) || (/Stripe-Signature:\s*t=1,v1=0{10}/.test(s) && /--data/.test(s))) {
    return {
      kind: "unknown",
      message: "This is the command itself. Run it in your terminal and paste what it prints: the endpoint list for step 1, or the response starting with the HTTP line for step 2.",
    };
  }
  if (/^curl: \(\d+\)/m.test(s) || /^HTTP\/[\d.]+\s+\d{3}\b/m.test(s) || /^\d{3}$/.test(s) || /^StatusCode\s*:\s*\d{3}\b/m.test(s)) return { kind: "signature" };
  if (/^[{[]/.test(s)) {
    if (/"object"\s*:\s*"webhook_endpoint"|"\/v1\/webhook_endpoints"|"enabled_events"/.test(s)) return { kind: "endpoints" };
    return { kind: "unknown", message: "This JSON is not a list of webhook endpoints. Run the command from step 1 and paste its output." };
  }
  if (detectStripeCode(s)) return { kind: "code" };
  const p = parseEndpoints(s);
  if (p.ok && p.source === "events") return { kind: "endpoints" };
  if (/\bstripe\b/i.test(s)) return { kind: "code" };
  return { kind: "unknown", message: ACCEPTED };
}

export type StripeResult = { ok: true; report: Report } | { ok: false; error: string };

export function runStripeCheck(raw: string): StripeResult {
  try {
    const input = detectStripeInput(raw);
    if (input.kind === "unknown") return { ok: false, error: input.message };
    const report = input.kind === "endpoints" ? endpointsReport(raw) : input.kind === "signature" ? signatureReport(raw) : codeReport(raw);
    if ("error" in report) return { ok: false, error: report.error };
    return { ok: true, report };
  } catch {
    return { ok: false, error: "The check could not be completed for this input. Copy the whole output again and retry." };
  }
}

export const stripeCommands = {
  listEndpoints: "stripe webhook_endpoints list --limit 100",
  listEndpointsLive: "stripe webhook_endpoints list --limit 100 --live",
  probe: probeCommand,
};
