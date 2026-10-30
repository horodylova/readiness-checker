import { describe, expect, test } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { detectStripeInput, runStripeCheck, stripeCommands } from "./index";
import { endpointRules, parseEndpoints } from "./endpoints";
import { parseProbeResponse, probeBody, signatureRules } from "./signature";
import { codeRules, screenCode } from "./code";
import type { Finding } from "../types";

const fx = (name: string) => readFileSync(join(__dirname, "fixtures", name), "utf8");
const rules = (f: Finding[]) => f.map((x) => x.rule).sort();
const has = (f: Finding[], rule: string, severity?: string) => f.some((x) => x.rule === rule && (!severity || x.severity === severity));
const now = new Date("2026-10-30T00:00:00Z");

describe("endpoints", () => {
  test("well configured endpoint produces nothing above info", () => {
    const p = parseEndpoints(fx("endpoints-good.json"));
    expect(p.ok).toBe(true);
    if (!p.ok) return;
    const f = endpointRules(p.endpoints, now);
    expect(f.filter((x) => x.severity !== "info")).toEqual([]);
  });
  test("broken list", () => {
    const p = parseEndpoints(fx("endpoints-bad.json"));
    expect(p.ok && p.warnings[0]).toContain("truncated");
    if (!p.ok) return;
    const f = endpointRules(p.endpoints, now);
    expect(has(f, "WH-02", "high")).toBe(true);
    expect(has(f, "WH-03", "high")).toBe(true);
    expect(has(f, "WH-04", "high")).toBe(true);
    expect(has(f, "WH-05", "low")).toBe(true);
    expect(has(f, "WH-07", "high")).toBe(true);
    expect(has(f, "WH-08", "medium")).toBe(true);
    expect(has(f, "WH-09", "high")).toBe(true);
    expect(has(f, "WH-10", "medium")).toBe(true);
    expect(has(f, "WH-13", "low")).toBe(true);
    expect(f[0].severity).toBe("high");
  });
  test("empty list is a finding of its own", () => {
    const f = endpointRules([], now);
    expect(rules(f)).toEqual(["WH-00"]);
  });
  test("wildcard subscription silences missing-event rules", () => {
    const f = endpointRules([{ url: "https://a.example/w", enabled_events: ["*"], status: "enabled", livemode: true }], now);
    expect(rules(f)).toEqual(["WH-06"]);
  });
  test("test-mode-only list is noted", () => {
    const f = endpointRules([{ url: "https://a.example/w", enabled_events: ["checkout.session.completed"], status: "enabled", livemode: false }], now);
    expect(has(f, "WH-01", "info")).toBe(true);
  });
  test("plain event list from the Dashboard", () => {
    const p = parseEndpoints("checkout.session.completed\ninvoice.payment_failed\ncustomer.subscription.deleted");
    expect(p.ok && p.source).toBe("events");
    if (!p.ok) return;
    const f = endpointRules(p.endpoints, now);
    expect(has(f, "WH-11")).toBe(true);
    expect(has(f, "WH-02")).toBe(false);
  });
  test("single endpoint object and bare array are accepted", () => {
    const one = JSON.parse(fx("endpoints-good.json")).data[0];
    expect(parseEndpoints(JSON.stringify(one)).ok).toBe(true);
    expect(parseEndpoints(JSON.stringify([one])).ok).toBe(true);
  });
  test("foreign JSON is refused", () => {
    expect(parseEndpoints('{"object":"customer","id":"cus_1"}').ok).toBe(false);
  });
});

describe("signature probe", () => {
  test("command targets the given address and carries an invalid signature", () => {
    const c = stripeCommands.probe("https://app.example.com/api/stripe/webhook");
    expect(c.ok).toBe(true);
    if (!c.ok) return;
    expect(c.command).toContain("https://app.example.com/api/stripe/webhook");
    expect(c.command).toContain("Stripe-Signature: t=1,v1=0000");
    expect(c.command).toContain("readiness.check.unsigned");
    expect(JSON.parse(probeBody).type).toBe("readiness.check.unsigned");
  });
  test("PowerShell variant uses curl.exe on one line", () => {
    const c = stripeCommands.probe("https://app.example.com/api/stripe/webhook");
    if (!c.ok) throw new Error(c.error);
    expect(c.powershell.startsWith("curl.exe -sS -i")).toBe(true);
    expect(c.powershell.includes("\n")).toBe(false);
    expect(c.powershell).toContain('\\"type\\":\\"readiness.check.unsigned\\"');
    expect(c.command).toContain("curl -sS -i");
  });
  test("Invoke-WebRequest style output is read", () => {
    const r = parseProbeResponse("StatusCode        : 400\nStatusDescription : Bad Request\nContent           : Webhook Error\nRawContent        : HTTP/1.1 400");
    expect(r.status).toBe(400);
  });
  test("command refuses private addresses", () => {
    expect(stripeCommands.probe("http://localhost:3000/webhook").ok).toBe(false);
  });
  test.each([
    ["HTTP/2 200\ncontent-type: application/json\n\n{\"received\":true}", "SIG-01", "critical"],
    ["HTTP/1.1 400 Bad Request\n\nWebhook Error: No signatures found", "SIG-00", "info"],
    ["200", "SIG-01", "critical"],
    ["HTTP/2 404\n\nnot found", "SIG-07", "info"],
    ["HTTP/2 405\n\n", "SIG-08", "medium"],
    ["HTTP/2 308\nlocation: https://www.app.example.com/api/webhook\n\n", "SIG-03", "high"],
    ["HTTP/2 500\n\nInternal Server Error", "SIG-02", "medium"],
    ["HTTP/2 200\n\n<!doctype html><html><body>app</body></html>", "SIG-09", "high"],
    ["HTTP/2 403\ncontent-type: text/html\n\n<!doctype html><html><title>Just a moment</title></html>", "SIG-10", "info"],
    ["curl: (6) Could not resolve host: app.example.com", "SIG-05", "info"],
    ["{\"received\":true}", "SIG-06", "info"],
  ])("%s", (output, rule, severity) => {
    const f = signatureRules(parseProbeResponse(output));
    expect(rules(f)).toEqual([rule]);
    expect(f[0].severity).toBe(severity);
  });
  test("last status line wins when curl prints a 100 Continue first", () => {
    const r = parseProbeResponse("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n");
    expect(r.status).toBe(400);
  });
});

describe("handler code", () => {
  test("good Next.js handler is clean", () => {
    expect(codeRules(fx("handler-good.txt"))).toEqual([]);
  });
  test("good Flask handler is clean", () => {
    expect(codeRules(fx("handler-python.txt"))).toEqual([]);
  });
  test("handler without verification", () => {
    const f = codeRules(fx("handler-bad.txt"));
    expect(has(f, "CODE-01", "critical")).toBe(true);
    expect(has(f, "CODE-06", "medium")).toBe(true);
    expect(has(f, "CODE-07", "high")).toBe(true);
    expect(has(f, "CODE-08", "medium")).toBe(true);
    expect(has(f, "CODE-09", "medium")).toBe(true);
  });
  test("handler that swallows verification errors", () => {
    const f = codeRules(fx("handler-swallow.txt"));
    expect(has(f, "CODE-02", "high")).toBe(true);
    expect(has(f, "CODE-04", "critical")).toBe(true);
    expect(has(f, "CODE-05", "high")).toBe(true);
    expect(has(f, "CODE-10", "medium")).toBe(true);
    expect(has(f, "CODE-01")).toBe(false);
  });
  test("checkout with client-set amount", () => {
    const f = codeRules(fx("checkout-bad.txt"));
    expect(has(f, "CHK-01", "critical")).toBe(true);
    expect(has(f, "CHK-03", "high")).toBe(true);
    expect(has(f, "CHK-04", "high")).toBe(true);
  });
  test("checkout with server-side price map is clean", () => {
    expect(codeRules(fx("checkout-good.txt"))).toEqual([]);
  });
  test("good Django and Rails handlers are clean, raw request.body is not a parsed body", () => {
    expect(codeRules(fx("handler-django.txt"))).toEqual([]);
    expect(codeRules(fx("handler-rails.txt"))).toEqual([]);
  });
  test("Flask handler verifying json.dumps of a parsed body, with a literal fallback secret", () => {
    const f = codeRules(fx("handler-flask-dumps.txt"));
    expect(has(f, "CODE-02", "high")).toBe(true);
    expect(has(f, "CODE-05", "high")).toBe(true);
  });
  test("price read from the database is not a client-set price", () => {
    expect(codeRules(fx("checkout-db-price.txt")).some((x) => x.rule === "CHK-01")).toBe(false);
  });
  test("the word webhook in a comment does not make checkout code a handler", () => {
    const f = codeRules(fx("checkout-comment-webhook.txt"));
    expect(f.some((x) => x.rule === "CODE-01")).toBe(false);
    expect(f).toEqual([]);
  });
  test("handler without a route string or header read is still a handler when it switches on event.type", () => {
    expect(has(codeRules(fx("handler-bad.txt")), "CODE-01", "critical")).toBe(true);
  });
  test("storing the verified event as JSON for idempotency is not re-serialised verification", () => {
    const src = `const event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
    await db.from("stripe_events").insert({ id: event.id, payload: JSON.stringify(event) });
    switch (event.type) { case "payment_intent.succeeded": await markPaid(event.data.object.id); }`;
    expect(codeRules(src).some((x) => x.rule === "CODE-02")).toBe(false);
  });
  test("empty-string fallback for the secret is not a literal secret", () => {
    const src = `const event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET || "");
    await db.stripeEvents.create({ data: { id: event.id } });`;
    expect(codeRules(src).some((x) => x.rule === "CODE-05")).toBe(false);
  });
  test("Python checkout with amount from the request", () => {
    const src = `data = request.get_json()
session = stripe.checkout.Session.create(
    mode="payment",
    client_reference_id=data["user"],
    line_items=[{"price_data": {"currency": "usd", "product_data": {"name": "x"}, "unit_amount": int(data["amount"])}, "quantity": 1}],
    success_url="https://a.example/ok", cancel_url="https://a.example/no")`;
    expect(codeRules(src).some((x) => x.rule === "CHK-01")).toBe(true);
  });
  test("pasted secrets are refused and not analysed", () => {
    const key = ["sk", "live", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"].join("_");
    const r = screenCode(`const stripe = new Stripe("${key}");`);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toContain("discarded");
    expect(r.error).not.toContain(key);
  });
  test("Supabase service role key and secret key are refused", () => {
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const service = `${b64({ alg: "HS256" })}.${b64({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "service_role" })}.${"s".repeat(43)}`;
    expect(screenCode(`const admin = createClient(url, "${service}");`).ok).toBe(false);
    expect(screenCode(`const k = "${["sb", "secret", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"].join("_")}";`).ok).toBe(false);
  });
  test("restricted test key is refused", () => {
    expect(screenCode(`const k = "${["rk", "test", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"].join("_")}";`).ok).toBe(false);
  });
  test("whsec literal is refused too", () => {
    const secret = ["whsec", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"].join("_");
    expect(screenCode(`constructEvent(body, sig, "${secret}")`).ok).toBe(false);
  });
});

describe("routing", () => {
  test.each([
    [fx("endpoints-good.json"), "endpoints"],
    ["checkout.session.completed\ninvoice.paid", "endpoints"],
    ["HTTP/2 200\n\nok", "signature"],
    ["400", "signature"],
    ["curl: (7) Failed to connect", "signature"],
    ["StatusCode        : 400\nStatusDescription : Bad Request", "signature"],
    [fx("handler-good.txt"), "code"],
    [fx("handler-python.txt"), "code"],
    [fx("checkout-bad.txt"), "code"],
    ['{"object":"customer"}', "unknown"],
    ["hello", "unknown"],
  ])("routes input %#", (input, kind) => {
    expect(detectStripeInput(input).kind).toBe(kind);
  });
  test("runStripeCheck returns reports with the right engine", () => {
    const a = runStripeCheck(fx("endpoints-bad.json"));
    expect(a.ok && a.report.engine).toBe("stripe-endpoints");
    const b = runStripeCheck("HTTP/2 200\n\n{}");
    expect(b.ok && b.report.engine).toBe("stripe-signature");
    expect(b.ok && b.report.summary.critical).toBe(1);
    const c = runStripeCheck(fx("handler-bad.txt"));
    expect(c.ok && c.report.engine).toBe("stripe-code");
    const d = runStripeCheck("hello");
    expect(d.ok).toBe(false);
  });
});
