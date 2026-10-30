import type { Finding, Report } from "../types";
import { sortFindings, summarise } from "../types";
import { parseTarget } from "../url/target";

export const PROBE_EVENT_TYPE = "readiness.check.unsigned";

export const probeBody = JSON.stringify({
  id: "evt_readiness_check_unsigned",
  object: "event",
  api_version: "2024-06-20",
  created: 0,
  livemode: false,
  type: PROBE_EVENT_TYPE,
  data: { object: { id: "rc_0", object: "readiness_check" } },
});

export function probeCommand(endpointUrl: string): { ok: true; command: string } | { ok: false; error: string } {
  const t = parseTarget(endpointUrl);
  if (!t.ok) return t;
  const body = probeBody.replace(/'/g, "'\\''");
  const command = [
    `curl -s -i -X POST '${t.url.toString().replace(/'/g, "%27")}'`,
    `  -H 'Content-Type: application/json'`,
    `  -H 'Stripe-Signature: t=1,v1=0000000000000000000000000000000000000000000000000000000000000000'`,
    `  --data '${body}'`,
  ].join(" \\\n");
  return { ok: true, command };
}

export type ProbeResponse = { status: number | null; body: string; headers: string; transportError: string | null };

export function parseProbeResponse(raw: string): ProbeResponse {
  const s = raw.replace(/\r/g, "").trim();
  const transport = s.match(/^curl: \(\d+\)[^\n]*/m);
  if (transport) return { status: null, body: "", headers: "", transportError: transport[0] };
  const statusLines = [...s.matchAll(/^HTTP\/[\d.]+\s+(\d{3})\b[^\n]*/gm)];
  if (statusLines.length) {
    const last = statusLines[statusLines.length - 1];
    const after = s.slice((last.index ?? 0) + last[0].length);
    const split = after.indexOf("\n\n");
    const headers = split >= 0 ? after.slice(0, split) : after;
    const body = split >= 0 ? after.slice(split + 2) : "";
    return { status: Number(last[1]), body: body.trim(), headers: headers.trim(), transportError: null };
  }
  const bare = s.match(/^(\d{3})$/);
  if (bare) return { status: Number(bare[1]), body: "", headers: "", transportError: null };
  return { status: null, body: s, headers: "", transportError: null };
}

export function signatureRules(resp: ProbeResponse): Finding[] {
  const out: Finding[] = [];
  const add = (f: Finding) => out.push(f);
  const obj = "webhook handler";

  if (resp.transportError) {
    add({
      rule: "SIG-05",
      severity: "info",
      object: obj,
      title: "The endpoint could not be reached",
      detail: `${resp.transportError}. The address may be wrong, the app may be down, or the host blocks requests without a browser user agent. Stripe deliveries would fail the same way.`,
      remedy: "Check the address and the deployment, then run the command again.",
    });
    return out;
  }
  if (resp.status === null) {
    add({
      rule: "SIG-06",
      severity: "info",
      object: obj,
      title: "No HTTP status in the output",
      detail: "The pasted text has no status line. The command includes -i so that the status is printed; paste the whole output.",
    });
    return out;
  }
  const code = resp.status;
  const bodyMentionsSignature = /signature|webhook secret|construct_?event/i.test(resp.body);
  const htmlPage = /<!doctype html|<html/i.test(resp.body);

  if (code >= 200 && code < 300 && htmlPage) {
    add({
      rule: "SIG-09",
      severity: "high",
      object: obj,
      title: "The address serves a page, not a handler",
      detail: `The ${code} answer is an HTML page. The route falls through to the app shell, so no webhook handler runs at this address and Stripe believes its deliveries succeed.`,
      remedy: "Check the endpoint path in Stripe against the route the handler is deployed on.",
    });
  } else if (code >= 200 && code < 300) {
    add({
      rule: "SIG-01",
      severity: "critical",
      object: obj,
      title: "Unsigned event accepted",
      detail: `The handler answered ${code} to an event with an invalid signature and an unknown type. Anyone who knows the address can send "payment succeeded" or "subscription active" and the handler will act on it.`,
      remedy:
        "Verify every delivery with the webhook signing secret before reading the event, using the raw request body, and reject with 400 when verification fails. Stripe's constructEvent (or construct_event) does this in every official library.",
    });
  } else if (code === 400 || code === 401 || code === 403) {
    add({
      rule: "SIG-00",
      severity: "info",
      object: obj,
      title: "Invalid signature rejected",
      detail: `The handler answered ${code}${bodyMentionsSignature ? " and named the signature check" : ""}. Forged events are refused.`,
    });
  } else if (code === 404) {
    add({
      rule: "SIG-07",
      severity: "info",
      object: obj,
      title: "Nothing listens at this address",
      detail: "The app answered 404. Either the address differs from the one registered in Stripe, or the handler is not deployed. If it is the registered address, Stripe gets the same 404 and no event is processed.",
      remedy: "Compare the address with the endpoint in Developers, Webhooks, and run the command on the exact one.",
    });
  } else if (code === 405) {
    add({
      rule: "SIG-08",
      severity: "medium",
      object: obj,
      title: "POST not accepted",
      detail: "The app answered 405. Stripe sends events as POST, so this address cannot receive them.",
      remedy: "Export a POST handler for this route and check the endpoint address in Stripe.",
    });
  } else if (code >= 300 && code < 400) {
    add({
      rule: "SIG-03",
      severity: "high",
      object: obj,
      title: "Endpoint redirects",
      detail: `The handler answered ${code}. Stripe does not follow redirects, so every event delivered to this address is dropped and the endpoint will be disabled after repeated failures.`,
      remedy: "Register the final address in Stripe (with or without www, with the exact path) so that the handler answers directly.",
    });
  } else if (code >= 500) {
    add({
      rule: "SIG-02",
      severity: "medium",
      object: obj,
      title: "Handler crashes on a bad signature",
      detail: `The handler answered ${code}. A failed verification should be a controlled 400. A crash means the error is not caught, so logs fill with stack traces, Stripe retries for up to three days, and a different malformed input may crash the handler before verification runs.`,
      remedy: "Wrap the verification in a try block and return 400 on failure. Confirm that nothing reads the body before verification.",
    });
  } else {
    add({
      rule: "SIG-04",
      severity: "low",
      object: obj,
      title: `Unexpected status ${code}`,
      detail: "The handler rejected the request, but with a status Stripe treats as a failed delivery. Stripe retries failed deliveries and disables the endpoint after a run of failures.",
      remedy: "Return 400 for a bad signature and 2xx once the event is accepted.",
    });
  }

  return sortFindings(out);
}

export const signatureNotChecked = [
  "Whether the webhook secret in the app matches the endpoint in Stripe. A wrong secret rejects real events the same way.",
  "What the handler does after a valid event. Step 3 covers that.",
  "Replay of an old, correctly signed event. The library rejects timestamps older than five minutes by default.",
];

export function signatureReport(raw: string): Report {
  const findings = signatureRules(parseProbeResponse(raw));
  return {
    engine: "stripe-signature",
    findings,
    summary: summarise(findings),
    notChecked: signatureNotChecked,
    warnings: [],
    next: ["Step 3: paste the handler code to check idempotency and the events it handles."],
  };
}
