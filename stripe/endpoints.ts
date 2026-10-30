import type { Finding, Report } from "../types";
import { sortFindings, summarise } from "../types";

export type WebhookEndpoint = {
  id?: string;
  url: string;
  status?: string;
  enabled_events: string[];
  livemode?: boolean;
  api_version?: string | null;
  description?: string | null;
};

export type EndpointsParse =
  | { ok: true; endpoints: WebhookEndpoint[]; source: "json" | "events"; warnings: string[] }
  | { ok: false; error: string };

const EVENT_NAME = /^[a-z_]+(\.[a-z_]+)+$|^\*$/;

function asEndpoint(v: unknown): WebhookEndpoint | null {
  if (!v || typeof v !== "object") return null;
  const o = v as Record<string, unknown>;
  if (o.object !== "webhook_endpoint" && !(typeof o.url === "string" && Array.isArray(o.enabled_events))) return null;
  return {
    id: typeof o.id === "string" ? o.id : undefined,
    url: typeof o.url === "string" ? o.url : "",
    status: typeof o.status === "string" ? o.status : undefined,
    enabled_events: Array.isArray(o.enabled_events) ? o.enabled_events.filter((e): e is string => typeof e === "string") : [],
    livemode: typeof o.livemode === "boolean" ? o.livemode : undefined,
    api_version: typeof o.api_version === "string" ? o.api_version : null,
    description: typeof o.description === "string" ? o.description : null,
  };
}

export function parseEndpoints(raw: string): EndpointsParse {
  const s = raw.trim();
  if (!s) return { ok: false, error: "Paste the output of the webhook endpoints command." };
  if (s.length > 2_000_000) return { ok: false, error: "The input is larger than 2 MB." };
  const warnings: string[] = [];

  const jsonStart = s.search(/[{[]/);
  if (jsonStart >= 0 && (jsonStart === 0 || /webhook_endpoints|git:|\$\s*$|➜/m.test(s.slice(0, jsonStart)))) {
    let data: unknown;
    try {
      data = JSON.parse(s.slice(jsonStart, Math.max(s.lastIndexOf("}"), s.lastIndexOf("]")) + 1));
    } catch {
      return { ok: false, error: "The input is not valid JSON. Copy the whole output of the command." };
    }
    const list: unknown[] = Array.isArray(data)
      ? data
      : data && typeof data === "object" && Array.isArray((data as { data?: unknown }).data)
        ? ((data as { data: unknown[] }).data as unknown[])
        : [data];
    const endpoints = list.map(asEndpoint).filter((e): e is WebhookEndpoint => e !== null);
    if (!endpoints.length && !(data && typeof data === "object" && (data as { object?: unknown }).object === "list")) {
      return { ok: false, error: "This JSON does not contain Stripe webhook endpoints. Run the command from this page and paste its output." };
    }
    if (data && typeof data === "object" && (data as { has_more?: unknown }).has_more === true) {
      warnings.push("The list is truncated at 100 endpoints. Run the command again with --starting-after and the last id in this output, or check the rest in Developers, Webhooks.");
    }
    return { ok: true, endpoints, source: "json", warnings };
  }

  const names = s
    .split(/[\s,;]+/)
    .map((x) => x.trim())
    .filter(Boolean);
  if (names.length && names.every((n) => EVENT_NAME.test(n))) {
    return {
      ok: true,
      endpoints: [{ url: "", enabled_events: names }],
      source: "events",
      warnings: ["Only the event list was provided, so endpoint status, address and API version are not checked."],
    };
  }
  return { ok: false, error: "Paste the JSON from the webhook endpoints command, or the list of event names from the Dashboard, one per line." };
}

const PAYMENT_CONFIRMATION = ["checkout.session.completed", "payment_intent.succeeded", "charge.succeeded", "invoice.paid", "invoice.payment_succeeded"];

function versionDate(v: string | null | undefined): Date | null {
  const m = (v ?? "").match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return null;
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  return Number.isNaN(d.getTime()) ? null : d;
}

export function endpointRules(endpoints: WebhookEndpoint[], now = new Date()): Finding[] {
  const out: Finding[] = [];
  const add = (f: Finding) => out.push(f);

  if (!endpoints.length) {
    add({
      rule: "WH-00",
      severity: "high",
      object: "webhook endpoints",
      title: "No webhook endpoint in this mode",
      detail:
        "The list is empty. The command shows test mode by default and live mode with --live, so check the other mode first. If both are empty, nothing tells your server when a payment succeeds, fails or is refunded: access granted on the success page can be reached without paying, and a failed renewal is never noticed.",
      remedy: "Run the command with --live. If that list is empty too, create an endpoint in Developers, Webhooks, and grant access from the event handler, never from the redirect page.",
    });
    return out;
  }

  const live = endpoints.filter((e) => e.livemode === true);
  if (endpoints.every((e) => e.livemode === false)) {
    add({
      rule: "WH-01",
      severity: "info",
      object: "webhook endpoints",
      title: "Test mode only",
      detail: "Every endpoint in this list is in test mode. If the app takes live payments, run the command with --live and check that list as well.",
    });
  }

  const byUrl = new Map<string, number>();
  for (const e of endpoints) byUrl.set(e.url, (byUrl.get(e.url) ?? 0) + 1);

  for (const e of endpoints) {
    const obj = e.url || e.id || "endpoint";
    const events = new Set(e.enabled_events);
    const all = events.has("*");
    const has = (name: string) => all || events.has(name);

    if (e.status && e.status !== "enabled") {
      add({
        rule: "WH-02",
        severity: live.length && e.livemode === false ? "low" : "high",
        object: obj,
        title: "Endpoint disabled",
        detail: `Status is ${e.status}. Stripe is not delivering events to it. Endpoints are disabled automatically after repeated failures, so the handler was likely failing.`,
        remedy: "Fix the handler, then enable the endpoint in Developers, Webhooks. Replay the missed events from the endpoint page.",
      });
    }

    if (/^http:\/\//i.test(e.url)) {
      add({
        rule: "WH-03",
        severity: "high",
        object: obj,
        title: "Endpoint over http",
        detail: "Events travel unencrypted and can be read or altered on the way.",
        remedy: "Change the endpoint address to https.",
      });
    }

    if (/localhost|127\.0\.0\.1|\.ngrok(-free)?\.(app|io|dev)|\.loca\.lt|\.trycloudflare\.com|\.local(host)?(\/|$)/i.test(e.url)) {
      add({
        rule: "WH-04",
        severity: e.livemode === true ? "high" : "info",
        object: obj,
        title: e.livemode === true ? "Live endpoint points at a development tunnel" : "Development tunnel endpoint",
        detail:
          e.livemode === true
            ? "Live events are being sent to a tunnel or local address that is not always running. Events are lost when it is down."
            : "A tunnel address is normal in test mode. Make sure the live endpoint points at the deployed app.",
        remedy: e.livemode === true ? "Point the live endpoint at the deployed app and replay the missed events." : undefined,
      });
    }

    if ((byUrl.get(e.url) ?? 0) > 1 && e.url) {
      add({
        rule: "WH-05",
        severity: "low",
        object: obj,
        title: "Duplicate endpoint",
        detail: "More than one endpoint delivers to the same address, so each event arrives more than once. Without idempotency every payment is processed twice.",
        remedy: "Keep one endpoint per address and delete the others.",
      });
    }

    if (all) {
      add({
        rule: "WH-06",
        severity: "info",
        object: obj,
        title: "Subscribed to every event",
        detail: "The handler receives every event type Stripe emits. That works, but each new event type Stripe adds reaches your code untested, and the volume hides failures in the delivery log.",
        remedy: "Subscribe to the events the handler actually processes.",
      });
    }

    if (!PAYMENT_CONFIRMATION.some(has) && !all) {
      add({
        rule: "WH-07",
        severity: "high",
        object: obj,
        title: "No event confirms a payment",
        detail: `None of ${PAYMENT_CONFIRMATION.join(", ")} is subscribed. The server never learns that a payment succeeded unless it trusts the redirect page, which anyone can open.`,
        remedy: "Subscribe to checkout.session.completed (Checkout) or payment_intent.succeeded (custom payment flow) and grant access from that event.",
      });
    }

    if (has("checkout.session.completed") && !has("checkout.session.async_payment_succeeded") && !all) {
      add({
        rule: "WH-08",
        severity: "medium",
        object: obj,
        title: "Delayed payment methods are not confirmed",
        detail:
          "Bank debits and some local methods complete the Checkout session before the money arrives. checkout.session.completed fires with payment_status unpaid, and the final result arrives as checkout.session.async_payment_succeeded or async_payment_failed, which are not subscribed.",
        remedy: "Subscribe to both async_payment events, or grant access only when payment_status is paid.",
      });
    }

    const subscriptions = [...events].some((n) => n.startsWith("customer.subscription.") || n.startsWith("invoice."));
    if (subscriptions && !all) {
      if (!has("customer.subscription.deleted")) {
        add({
          rule: "WH-09",
          severity: "high",
          object: obj,
          title: "Cancelled subscriptions are not revoked",
          detail: "Subscription events are in use, but customer.subscription.deleted is not subscribed. When a subscription ends, the customer keeps access.",
          remedy: "Subscribe to customer.subscription.deleted and remove access in the handler.",
        });
      }
      if (!has("invoice.payment_failed")) {
        add({
          rule: "WH-10",
          severity: "medium",
          object: obj,
          title: "Failed renewals are not handled",
          detail: "invoice.payment_failed is not subscribed. A card that expires keeps the customer on the paid plan until Stripe gives up and cancels, typically weeks later, with no message from your app.",
          remedy: "Subscribe to invoice.payment_failed and notify the customer or limit access.",
        });
      }
      if (!has("customer.subscription.updated")) {
        add({
          rule: "WH-11",
          severity: "medium",
          object: obj,
          title: "Plan changes are not tracked",
          detail: "customer.subscription.updated is not subscribed. Upgrades, downgrades, pauses and trial endings do not reach the app.",
          remedy: "Subscribe to customer.subscription.updated and update the stored plan and status.",
        });
      }
    }

    if (!has("charge.dispute.created") && !all) {
      add({
        rule: "WH-12",
        severity: "low",
        object: obj,
        title: "Disputes are not tracked",
        detail: "charge.dispute.created is not subscribed. A chargeback is only visible in the Dashboard, and the response deadline is easy to miss.",
        remedy: "Subscribe to charge.dispute.created and alert yourself.",
      });
    }

    const vd = versionDate(e.api_version);
    if (vd && now.getTime() - vd.getTime() > 2 * 365 * 24 * 3600 * 1000) {
      add({
        rule: "WH-13",
        severity: "low",
        object: obj,
        title: "Old API version pinned",
        detail: `Events are delivered in the ${e.api_version} format. Field names and defaults changed since then, and library updates will expect the newer shape.`,
        remedy: "Upgrade the endpoint's API version together with the Stripe library and test the handler on the new event shape.",
      });
    }
  }

  return sortFindings(out);
}

export const endpointsNotChecked = [
  "Whether the handler verifies the signature. Step 2 covers that.",
  "What the handler does with each event. Step 3 covers that.",
  "Endpoints in the other mode (test or live) when only one list was pasted.",
  "Connect endpoints listening for connected accounts.",
];

export function endpointsReport(raw: string): Report | { error: string } {
  const parsed = parseEndpoints(raw);
  if (!parsed.ok) return { error: parsed.error };
  const findings = endpointRules(parsed.endpoints);
  return {
    engine: "stripe-endpoints",
    findings,
    summary: summarise(findings),
    notChecked: endpointsNotChecked,
    warnings: parsed.warnings,
    next: parsed.endpoints.length
      ? ["Step 2: test the signature check on each endpoint address with the command from this page."]
      : ["Run the same command with --live and paste that list as well."],
  };
}
