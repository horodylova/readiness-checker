import type { Finding, Report } from "../types";
import { sortFindings, summarise } from "../types";
import { findSecrets } from "../url/secrets";

const VERIFY = /\b(constructEvent(Async)?|construct_event|ConstructEvent(WithOptions)?|Webhook::constructEvent)\s*\(/;
const CHECKOUT_CREATE = /\b(checkout\.sessions\.create|checkout\.Session\.create|Checkout\\Session::create|checkout\.Sessions\.New|CheckoutSession\.create|Checkout::Session\.create)\s*\(/;
const PAYMENT_INTENT_CREATE = /\b(paymentIntents\.create|PaymentIntent\.create|PaymentIntent::create|paymentintent\.New)\s*\(/;

function section(src: string, start: number, length = 1800): string {
  return src.slice(start, start + length);
}

function stripStrings(src: string): string {
  return src.replace(/(["'`])(?:\\.|(?!\1)[^\\\n])*\1/g, (m) => m[0] + " ".repeat(Math.max(0, m.length - 2)) + m[0]);
}

export function detectStripeCode(src: string): boolean {
  return /\bstripe\b/i.test(src) && (VERIFY.test(src) || CHECKOUT_CREATE.test(src) || PAYMENT_INTENT_CREATE.test(src) || /webhook/i.test(src));
}

export type CodeParse = { ok: true; warnings: string[] } | { ok: false; error: string };

export function screenCode(src: string): CodeParse {
  if (src.length > 400_000) return { ok: false, error: "The input is larger than 400 KB. Paste the webhook handler and the checkout code only." };
  const secrets = findSecrets(src, "pasted code").filter((h) => /STRIPE|PRIVATE-KEY|DB-URL|OPENAI|ANTHROPIC|AWS|GITHUB/.test(h.pattern.id));
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
  const code = stripStrings(src);
  const hasWebhook = /webhook|constructEvent|construct_event|ConstructEvent|Stripe-Signature|stripe-signature/i.test(src);
  const verify = VERIFY.exec(code);
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
      const call = section(code, verify.index, 400);
      const before = code.slice(Math.max(0, verify.index - 1500), verify.index);
      if (/JSON\.stringify\s*\(/.test(call)) {
        add({
          rule: "CODE-02",
          severity: "high",
          object: handler,
          title: "Verification runs on re-serialised JSON",
          detail: "The body is parsed and then stringified again before verification. The signature covers the exact bytes Stripe sent, so this check either always fails, in which case deliveries are rejected, or the failure is swallowed and events are processed unverified.",
          remedy: "Read the raw body (request.text() in Next.js and Hono, express.raw({ type: 'application/json' }) in Express, request.get_data() in Flask) and pass it to the verification unchanged.",
        });
      } else if (/\b(req(uest)?\.body|await\s+req(uest)?\.json\(\)|body\s*=\s*await\s+req(uest)?\.json\(\))/.test(before + call) && !/\b(raw|text\(\)|rawBody|arrayBuffer\(\)|Buffer|get_data|getRawBody|bodyParser\.raw|express\.raw|type:\s*["']\*\/\*)/.test(src)) {
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
      if (/\bwebhooks\.constructEvent\s*\(\s*[^,]+,\s*[^,]+,\s*(process\.env\.\w+\s*(\|\||\?\?)\s*["'`]|["'`])/.test(src)) {
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
    const call = section(code, checkout.index, 2500);
    const callSrc = section(src, checkout.index, 2500);
    const obj = "checkout";
    const amountFromRequest = /\b(unit_amount|amount)\s*:\s*(?:Math\.\w+\(|Number\(|parseInt\(|parseFloat\(|\+)?\s*(req(uest)?\.|body\.|json\.|params\.|searchParams|formData|form\.|payload\.|input\.|args\.|data\.|amount\b|price\b|total\b)/;
    if (amountFromRequest.test(call) && !/\bunit_amount\s*:\s*\d+/.test(call)) {
      add({
        rule: "CHK-01",
        severity: "critical",
        object: obj,
        title: "Price comes from the request",
        detail: "The amount charged is taken from a value the browser sends. A visitor can edit it and pay one cent for anything.",
        remedy: "Look the price up on the server from the product or plan the customer chose, or use a Price ID created in the Dashboard.",
      });
    }
    const priceFromRequest = /\bprice\s*:\s*(req(uest)?\.|body\.|json\.|params\.|searchParams|formData|form\.|payload\.|input\.|args\.|data\.|priceId\b|price_id\b)/;
    if (priceFromRequest.test(call) && !/\b(includes|has|indexOf|allowed|ALLOWED|whitelist|PRICES|prices\[|plans\[|PLANS|switch|lookup|findUnique|findFirst|from\(|select)\b/.test(code.slice(Math.max(0, checkout.index - 2500), checkout.index + 2500))) {
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
