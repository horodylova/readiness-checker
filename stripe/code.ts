import type { Finding, Report } from "../types";
import { sortFindings, summarise } from "../types";
import { findSecrets } from "../url/secrets";

const VERIFY = /\b(constructEvent(Async)?|construct_event|ConstructEvent(WithOptions)?|Webhook::constructEvent)\s*\(/;
const CHECKOUT_CREATE = /\b(checkout\.sessions\.create|checkout\.Session\.create|Checkout\\Session::create|checkout\.Sessions\.New|CheckoutSession\.create|Checkout::Session\.create)\s*\(/;
const PAYMENT_INTENT_CREATE = /\b(paymentIntents\.create|PaymentIntent\.create|PaymentIntent::create|paymentintent\.New)\s*\(/;

function section(src: string, start: number, length = 1800): string {
  return src.slice(start, start + length);
}

function callArguments(src: string, start: number): string {
  const open = src.indexOf("(", start);
  if (open < 0) return "";
  let depth = 0;
  for (let i = open; i < src.length && i < open + 2000; i++) {
    const ch = src[i];
    if (ch === "(") depth += 1;
    else if (ch === ")") {
      depth -= 1;
      if (depth === 0) return src.slice(open + 1, i);
    }
  }
  return src.slice(open + 1, open + 2000);
}

function stripStrings(src: string): string {
  return src.replace(/(["'`])(?:\\.|(?!\1)[^\\\n])*\1/g, (m) => m[0] + " ".repeat(Math.max(0, m.length - 2)) + m[0]);
}

function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:\\"'`])\/\/[^\n]*/g, (m, lead) => lead + " ".repeat(m.length - lead.length))
    .replace(/(^|[^"'`$])#(?!\{)[^\n]*/gm, (m, lead) => lead + " ".repeat(m.length - lead.length));
}

const REQUEST_ROOTS = ["req", "request", "searchParams", "formData", "$_POST", "$_GET", "$_REQUEST"];

function requestBoundNames(code: string): Set<string> {
  const names = new Set<string>();
  const re = /(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:req(?:uest)?\.(?:json|formData|text)\s*\(\)|req(?:uest)?\.(?:body|query|params)\b|JSON\.parse\s*\(|request\.(?:get_json|form|json|args)\b|\$request->(?:all|input|json|post)\s*\(|params\.permit|JSON\.parse\s*\(\s*request\.body)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code))) {
    const target = m[1];
    if (target.startsWith("{")) {
      for (const part of target.slice(1, -1).split(",")) {
        const name = part.split(":").pop()?.split("=")[0]?.trim();
        if (name) names.add(name);
      }
    } else {
      names.add(target);
    }
  }
  const py = /^\s*([A-Za-z_]\w*)\s*=\s*(?:request\.(?:get_json|json|form|args)|json\.loads\s*\(\s*request)/gm;
  while ((m = py.exec(code))) names.add(m[1]);
  return names;
}

function fromRequest(expr: string, names: Set<string>): boolean {
  const root = expr.match(/^[$]?[A-Za-z_][\w$]*/)?.[0];
  if (!root) return false;
  return REQUEST_ROOTS.includes(root) || names.has(root);
}

export function detectStripeCode(src: string): boolean {
  return /\bstripe\b/i.test(src) && (VERIFY.test(src) || CHECKOUT_CREATE.test(src) || PAYMENT_INTENT_CREATE.test(src) || /webhook/i.test(src));
}

export type CodeParse = { ok: true; warnings: string[] } | { ok: false; error: string };

export function screenCode(src: string): CodeParse {
  if (src.length > 400_000) return { ok: false, error: "The input is larger than 400 KB. Paste the webhook handler and the checkout code only." };
  const secrets = findSecrets(src, "pasted code").filter((h) => h.pattern.id !== "SEC-GOOGLE-AI");
  if (secrets.length) {
    const names = [...new Set(secrets.map((h) => h.pattern.name))].join(", ");
    return {
      ok: false,
      error: `The code contains what looks like a secret (${names}). The input was discarded and not analysed. Move the value to an environment variable, then paste the code again.`,
    };
  }
  return { ok: true, warnings: [] };
}

export function codeRules(src: string): Finding[] {
  const out: Finding[] = [];
  const add = (f: Finding) => out.push(f);
  const noComments = stripComments(stripStrings(src));
  const code = noComments;
  const srcNoComments = stripComments(src);
  const hasWebhook =
    VERIFY.test(code) ||
    /stripe-signature|HTTP_STRIPE_SIGNATURE/i.test(srcNoComments) ||
    /webhook/i.test(code) ||
    /\b(post|route|path|get|all|handle|match)\b[^\n]{0,80}["'`][^"'`\n]*webhook/i.test(srcNoComments) ||
    /\b(event|evt)\s*(\.type\b|\.data\.object\b|\[\s*["']type["']\s*\])/.test(srcNoComments) ||
    /["'](checkout\.session\.completed|payment_intent\.succeeded|invoice\.paid|invoice\.payment_failed|customer\.subscription\.\w+)["']/.test(srcNoComments);
  const verify = VERIFY.exec(code);
  const pythonOrRuby = /\bconstruct_event\b/.test(code);
  const handler = "webhook handler";

  if (hasWebhook) {
    if (!verify) {
      add({
        rule: "CODE-01",
        severity: "critical",
        object: handler,
        title: "Signature is not verified",
        detail: "The handler reads the event without calling the Stripe library's signature check. Anyone who knows the address can send a forged event and the handler will act on it.",
        remedy: "Pass the raw request body, the Stripe-Signature header and the endpoint's signing secret to the library's constructEvent (or construct_event) before touching the event, and return 400 when it throws.",
      });
    } else {
      const call = callArguments(code, verify.index);
      const before = code.slice(Math.max(0, verify.index - 1500), verify.index);
      if (/JSON\.stringify\s*\(|json\.dumps\s*\(|json_encode\s*\(|to_json\b/.test(call)) {
        add({
          rule: "CODE-02",
          severity: "high",
          object: handler,
          title: "Verification runs on re-serialised JSON",
          detail: "The body is parsed and then stringified again before verification. The signature covers the exact bytes Stripe sent, so this check either always fails, in which case deliveries are rejected, or the failure is swallowed and events are processed unverified.",
          remedy: "Read the raw body (request.text() in Next.js and Hono, express.raw({ type: 'application/json' }) in Express, request.get_data() in Flask) and pass it to the verification unchanged.",
        });
      } else if (
        !pythonOrRuby &&
        /\b(req(uest)?\.body|await\s+req(uest)?\.json\(\)|body\s*=\s*await\s+req(uest)?\.json\(\))/.test(before + call) &&
        !/\b(raw|text\(\)|rawBody|arrayBuffer\(\)|Buffer|get_data|getRawBody|bodyParser\.raw|express\.raw|type:\s*["']\*\/\*)/.test(src)
      ) {
        add({
          rule: "CODE-03",
          severity: "medium",
          object: handler,
          title: "Body may be parsed before verification",
          detail: "The verification receives req.body or a parsed JSON value and nothing in the paste reads the raw body. If a JSON body parser runs on this route, the signature never matches.",
          remedy: "Disable JSON parsing for this route and pass the raw bytes to the verification. In Express use express.raw on the webhook path only.",
        });
      }
      const after = section(code, verify.index, 1200);
      const catchBlock = after.match(/catch\s*(\([^)]*\))?\s*\{([^}]*)\}/);
      if (catchBlock && !/\b(return|throw|res\.|response|Response|status\s*\(|abort|exit|sys\.exit|http\.Error|w\.WriteHeader|render|halt)\b/.test(catchBlock[2])) {
        add({
          rule: "CODE-04",
          severity: "critical",
          object: handler,
          title: "Verification failure does not stop the handler",
          detail: "The catch block after the signature check logs the error and continues. A forged event fails verification and is still processed.",
          remedy: "Return 400 from the catch block.",
        });
      }
      const literalSecret =
        /\bconstructEvent(Async)?\s*\(\s*[^,]+,\s*[^,]+,\s*(process\.env\.\w+\s*(\|\||\?\?)\s*["'`](?!["'`])|Deno\.env\.get\([^)]*\)\s*(\|\||\?\?)\s*["'`](?!["'`])|["'`](?!["'`]))/.test(srcNoComments) ||
        /\bconstruct_event\s*\([\s\S]{0,200}?os\.(environ\.get|getenv)\s*\([^)]*,\s*["'](?!["'])/.test(srcNoComments) ||
        /\bconstruct_event\s*\([\s\S]{0,200}?ENV\.fetch\s*\([^)]*,\s*["'](?!["'])/.test(srcNoComments) ||
        /\bconstructEvent\s*\([\s\S]{0,200}?(getenv|env)\s*\([^)]*\)\s*(\?:|\?\?)\s*["'](?!["'])/.test(srcNoComments) ||
        /\bconstruct_event\s*\(\s*[^,]+,\s*[^,]+,\s*["'](?!["'])/.test(srcNoComments);
      if (literalSecret) {
        add({
          rule: "CODE-05",
          severity: "high",
          object: handler,
          title: "Signing secret has a literal fallback",
          detail: "The verification falls back to a hardcoded value when the environment variable is missing. In a deployment without the variable the check still passes with a secret an attacker can read from the repository.",
          remedy: "Fail at startup when the secret is missing. No fallback.",
        });
      }
    }

    const EVENT_ID = /\b(event|evt|e)\s*(\.id\b|\[\s*["']id["']\s*\])/;
    const usesEventId = EVENT_ID.test(src.replace(/console\.\w+\([^)]*\)|logger\.\w+\([^)]*\)|print\([^)]*\)|log\.\w+\([^)]*\)/g, ""));
    const persists = /\b(processed|handled|seen|delivered)_?events?\b|\bevent_?id\b|stripe_event|idempoten|upsert|onConflict|ON CONFLICT|unique|INSERT IGNORE|findUnique|setnx|SETNX/i.test(src);
    if (!(usesEventId && persists)) {
      add({
        rule: "CODE-06",
        severity: "medium",
        object: handler,
        title: "No idempotency",
        detail: "Nothing records event.id, so a redelivered event is processed again. Stripe retries whenever the handler is slow or answers with an error, and the same event can also arrive twice. Credits are granted twice, emails sent twice, subscriptions renewed twice.",
        remedy: "Store event.id with a unique constraint before processing and skip the event when the insert fails.",
      });
    }

    const subscriptionEvents = /customer\.subscription\.|invoice\./.test(src);
    const handles = (name: string) => src.includes(name);
    if (subscriptionEvents) {
      if (!handles("customer.subscription.deleted")) {
        add({
          rule: "CODE-07",
          severity: "high",
          object: handler,
          title: "customer.subscription.deleted is not handled",
          detail: "The handler processes subscription events but never removes access when a subscription ends.",
          remedy: "Handle customer.subscription.deleted and mark the account as unpaid.",
        });
      }
      if (!handles("invoice.payment_failed")) {
        add({
          rule: "CODE-08",
          severity: "medium",
          object: handler,
          title: "invoice.payment_failed is not handled",
          detail: "A failed renewal reaches the handler and is ignored. The customer keeps access until Stripe cancels the subscription, often weeks later.",
          remedy: "Handle invoice.payment_failed: notify the customer and set the account to past due.",
        });
      }
    }

    if (handles("checkout.session.completed") && !/payment_status/.test(src) && !handles("checkout.session.async_payment_succeeded")) {
      add({
        rule: "CODE-09",
        severity: "medium",
        object: handler,
        title: "Access granted before the payment settles",
        detail: "checkout.session.completed is treated as paid. With bank debits and some local methods the session completes first and the money arrives later or not at all; the event then carries payment_status unpaid.",
        remedy: "Grant access only when session.payment_status is paid, and handle checkout.session.async_payment_succeeded and async_payment_failed.",
      });
    }

    const catchAll = code.match(/catch\s*(\([^)]*\))?\s*\{([^}]*)\}/g) ?? [];
    if (catchAll.some((c) => /\b(200|received:\s*true|ok:\s*true|sendStatus\(200\)|json\(\s*\{\s*received)/.test(c))) {
      add({
        rule: "CODE-10",
        severity: "medium",
        object: handler,
        title: "Processing errors are answered with 200",
        detail: "A catch block returns success. Stripe marks the delivery as done and never retries, so a failed database write silently loses the payment.",
        remedy: "Return 500 from the catch block so that Stripe retries, and keep the handler idempotent so the retry is safe.",
      });
    }
  }

  const checkout = CHECKOUT_CREATE.exec(code) ?? PAYMENT_INTENT_CREATE.exec(code);
  if (checkout) {
    const call = section(srcNoComments, checkout.index, 2500);
    const callSrc = call;
    const obj = "checkout";
    const bound = requestBoundNames(code);
    const amountExpr = call.match(/\b(unit_amount|amount)["']?\s*(?::|=>|=(?!=))\s*(?:(?:Math\.\w+|Number|parseInt|parseFloat|int|float|round|intval|\(int\))\s*\(\s*)?\+?\s*([$]?[A-Za-z_][\w$]*(?:\.[\w$]+|\[[^\]]*\]|->\w+)*)/);
    if (amountExpr && fromRequest(amountExpr[2], bound) && !/\bunit_amount\s*:\s*\d+/.test(call)) {
      add({
        rule: "CHK-01",
        severity: "critical",
        object: obj,
        title: "Price comes from the request",
        detail: "The amount charged is taken from a value the browser sends. A visitor can edit it and pay one cent for anything.",
        remedy: "Look the price up on the server from the product or plan the customer chose, or use a Price ID created in the Dashboard.",
      });
    }
    const priceExpr = call.match(/\bprice["']?\s*(?::|=>|=(?!=))\s*([$]?[A-Za-z_][\w$]*(?:\.[\w$]+|\[[^\]]*\]|->\w+)*)/);
    const priceRoot = priceExpr?.[1].match(/^[$]?[A-Za-z_][\w$]*/)?.[0] ?? "";
    const priceLooksClientSupplied = priceExpr ? fromRequest(priceExpr[1], bound) || /^price_?id$/i.test(priceRoot) : false;
    if (priceLooksClientSupplied && !/\b(includes|has|indexOf|allowed|ALLOWED|whitelist|PRICES|prices\[|plans\[|PLANS|switch|lookup|findUnique|findFirst|from\(|select)\b/.test(code.slice(Math.max(0, checkout.index - 2500), checkout.index + 2500))) {
      add({
        rule: "CHK-02",
        severity: "medium",
        object: obj,
        title: "Price ID is not checked against a list",
        detail: "The Price ID comes from the request and is used as is. A visitor can substitute any price that exists in your account, including a cheaper plan or an old discounted one.",
        remedy: "Map the plan name to a Price ID on the server, or check the ID against the list of prices you sell.",
      });
    }
    if (CHECKOUT_CREATE.test(code) && !/\b(client_reference_id|metadata|customer\b|customer_email|subscription_data)/.test(callSrc)) {
      add({
        rule: "CHK-03",
        severity: "high",
        object: obj,
        title: "Session is not linked to a user",
        detail: "The Checkout session carries no client_reference_id, metadata or customer. When checkout.session.completed arrives, the handler has no way to know which account paid.",
        remedy: "Set client_reference_id to the user ID, or create a Stripe customer per user and pass customer.",
      });
    }
    if (/\bsuccess_url\s*:/.test(call) && /\b(success|paid|status)=(true|1|paid|success)/.test(callSrc) && !hasWebhook) {
      add({
        rule: "CHK-04",
        severity: "high",
        object: obj,
        title: "Success page may be trusted as proof of payment",
        detail: "success_url carries a flag such as success=true and no webhook handler was pasted. If the app marks the order paid when that page opens, anyone can open the page without paying.",
        remedy: "Mark the order paid only from the webhook event, and treat the success page as a message to the customer.",
      });
    }
    if (/\bmode\s*:\s*["']subscription["']/.test(callSrc) && !/\bcustomer\b/.test(callSrc)) {
      add({
        rule: "CHK-05",
        severity: "low",
        object: obj,
        title: "Subscription without a reused customer",
        detail: "Each subscription checkout creates a new Stripe customer. A returning user gets a second customer record, and their old subscription is never found by the new one.",
        remedy: "Store the Stripe customer ID per user and pass customer on every subsequent checkout.",
      });
    }
  }

  if (/\bstripeAccount\b|stripe_account\b|Stripe-Account|transfer_data|application_fee_amount|transfers\.create/.test(src) && !/account\.updated|payouts_enabled|charges_enabled/.test(src)) {
    add({
      rule: "CON-01",
      severity: "low",
      object: "connect",
      title: "Connected account status is not checked",
      detail: "Money is routed to connected accounts, but nothing in the paste handles account.updated or checks charges_enabled and payouts_enabled. A transfer to an account that has not finished onboarding fails or is held.",
      remedy: "Handle account.updated and check charges_enabled and payouts_enabled before routing funds.",
    });
  }

  return sortFindings(out);
}

export const codeNotChecked = [
  "Whether the pasted handler is the one deployed. Step 2 tests the live address.",
  "Code that was not pasted: the success page, the database layer, middleware.",
  "Correctness of business logic, such as which plan grants which access.",
  "Stripe Dashboard settings: Radar rules, payment methods, email receipts.",
];

export function codeReport(raw: string): Report | { error: string } {
  const screened = screenCode(raw);
  if (!screened.ok) return { error: screened.error };
  const findings = codeRules(raw);
  const warnings = [...screened.warnings];
  if (!detectStripeCode(raw)) warnings.push("No Stripe webhook or Checkout call was recognised in the paste. The rules below only apply to such code.");
  return {
    engine: "stripe-code",
    findings,
    summary: summarise(findings),
    notChecked: codeNotChecked,
    warnings,
  };
}
