import type { DetectedStack, Finding, Report } from "../types";
import { sortFindings, summarise } from "../types";
import { checkHost, parseTarget } from "./target";
import { decodeJwtPayload, findSecrets, redact, type SecretHit } from "./secrets";

export type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;

export type ScanOptions = {
  fetch?: Fetcher;
  maxScripts?: number;
  maxSourceMaps?: number;
  maxBytes?: number;
  maxTotalBytes?: number;
  timeoutMs?: number;
  totalTimeoutMs?: number;
  probeSupabase?: boolean;
};

type Fetched = { url: string; status: number; contentType: string; body: string; truncated: boolean };

type Budget = { deadline: number; bytesLeft: number; timeoutMs: number };

const USER_AGENT = "HorodylovaReadinessCheck/1.0 (+https://horodylova-ltd.co.uk/tools)";

const EXPOSED_FILES: { path: string; id: string; title: string; test: (body: string) => boolean; severity: Finding["severity"] }[] = [
  { path: "/.env", id: "FILE-ENV", title: "Environment file is public", test: isEnvFile, severity: "critical" },
  { path: "/.env.local", id: "FILE-ENV", title: "Environment file is public", test: isEnvFile, severity: "critical" },
  { path: "/.env.production", id: "FILE-ENV", title: "Environment file is public", test: isEnvFile, severity: "critical" },
  { path: "/.git/config", id: "FILE-GIT", title: "Git repository is public", test: (b) => /^\s*\[core\]/m.test(b), severity: "high" },
  { path: "/.git/HEAD", id: "FILE-GIT", title: "Git repository is public", test: (b) => /^ref: refs\/heads\//.test(b.trim()), severity: "high" },
];

const PLATFORM_SUFFIXES = [
  "lovable.app",
  "lovableproject.com",
  "vercel.app",
  "netlify.app",
  "pages.dev",
  "workers.dev",
  "web.app",
  "firebaseapp.com",
  "github.io",
  "gitlab.io",
  "replit.app",
  "repl.co",
  "base44.app",
  "framer.app",
  "framer.website",
  "webflow.io",
  "bolt.host",
  "onrender.com",
  "fly.dev",
  "herokuapp.com",
  "azurewebsites.net",
  "amplifyapp.com",
  "surge.sh",
  "glitch.me",
];

const GENERIC_SECOND_LEVEL = new Set(["co", "com", "org", "net", "ac", "gov", "edu", "ltd", "plc", "me", "or", "ne", "go", "in", "id", "sch", "nhs", "police", "mil", "info", "biz", "web", "firm", "gen", "nom", "pro"]);

function isEnvFile(body: string): boolean {
  if (/<html|<!doctype/i.test(body.slice(0, 500))) return false;
  const lines = body.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith("#"));
  if (!lines.length) return false;
  const kv = lines.filter((l) => /^\s*(export\s+)?[A-Z][A-Z0-9_]*\s*=/.test(l));
  return kv.length >= 1 && kv.length / lines.length >= 0.6;
}

async function readLimited(res: Response, max: number): Promise<{ body: string; truncated: boolean }> {
  if (!res.body) {
    const text = await res.text();
    return text.length > max ? { body: text.slice(0, max), truncated: true } : { body: text, truncated: false };
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      chunks.push(value.slice(0, value.byteLength - (size - max)));
      truncated = true;
      await reader.cancel().catch(() => undefined);
      break;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(chunks.reduce((n, c) => n + c.byteLength, 0));
  let o = 0;
  for (const c of chunks) {
    all.set(c, o);
    o += c.byteLength;
  }
  return { body: new TextDecoder().decode(all), truncated };
}

async function get(fetcher: Fetcher, url: string, budget: Budget, opts: { maxBytes: number; headers?: Record<string, string> }): Promise<Fetched | null> {
  let current = url;
  for (let hop = 0; hop < 5; hop++) {
    const remaining = budget.deadline - Date.now();
    if (remaining <= 0 || budget.bytesLeft <= 0) return null;
    let host: string;
    try {
      host = new URL(current).hostname;
    } catch {
      return null;
    }
    if (checkHost(host)) return null;
    const max = Math.min(opts.maxBytes, budget.bytesLeft);
    try {
      const res = await fetcher(current, {
        redirect: "manual",
        headers: { "user-agent": USER_AGENT, accept: "*/*", ...(opts.headers ?? {}) },
        signal: AbortSignal.timeout(Math.min(budget.timeoutMs, remaining)),
      });
      if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
        const next = new URL(res.headers.get("location")!, current);
        if (next.protocol !== "https:" && next.protocol !== "http:") return null;
        if (next.port && next.port !== "80" && next.port !== "443") return null;
        if (next.username || next.password) return null;
        current = next.toString();
        continue;
      }
      const { body, truncated } = await readLimited(res, max);
      budget.bytesLeft -= body.length;
      return { url: current, status: res.status, contentType: res.headers.get("content-type") ?? "", body, truncated };
    } catch {
      return null;
    }
  }
  return null;
}

export function extractScripts(html: string, base: string): { external: string[]; inline: string[] } {
  const external = new Set<string>();
  const inline: string[] = [];
  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m: RegExpExecArray | null;
  while ((m = scriptRe.exec(html))) {
    const src = m[1].match(/\bsrc\s*=\s*["']([^"']+)["']/i)?.[1];
    if (src) {
      try {
        external.add(new URL(src, base).toString());
      } catch {}
    } else if (m[2].trim() && !/type\s*=\s*["']application\/(ld\+json|json)["']/i.test(m[1])) {
      inline.push(m[2]);
    }
  }
  const linkRe = /<link\b([^>]*)>/gi;
  while ((m = linkRe.exec(html))) {
    const attrs = m[1];
    if (/rel\s*=\s*["'](modulepreload|preload)["']/i.test(attrs) && (/modulepreload/i.test(attrs) || /as\s*=\s*["']script["']/i.test(attrs))) {
      const href = attrs.match(/\bhref\s*=\s*["']([^"']+)["']/i)?.[1];
      if (href) {
        try {
          external.add(new URL(href, base).toString());
        } catch {}
      }
    }
  }
  return { external: [...external], inline };
}

export function chunkReferences(js: string, base: string): string[] {
  const out = new Set<string>();
  const re = /["'`](\/?(?:_next\/static\/chunks|assets|static\/js)\/[A-Za-z0-9_\-./[\]%]+\.js)["'`]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(js))) {
    try {
      out.add(new URL(m[1].startsWith("/") ? m[1] : `/${m[1]}`, base).toString());
    } catch {}
  }
  return [...out];
}

export function siteKey(url: string): string {
  const host = new URL(url).hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (/^[\d.]+$/.test(host) || host.includes(":")) return host;
  if (PLATFORM_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`))) return host;
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const secondLevel = parts[parts.length - 2];
  const tld = parts[parts.length - 1];
  const keep = tld.length === 2 && GENERIC_SECOND_LEVEL.has(secondLevel) ? 3 : 2;
  return parts.slice(-keep).join(".");
}

export function sameSite(a: string, b: string): boolean {
  try {
    return siteKey(a) === siteKey(b);
  } catch {
    return false;
  }
}

function detectFrameworks(html: string, scripts: string[]): string[] {
  const all = `${html}\n${scripts.join("\n")}`;
  const out: string[] = [];
  if (/\/_next\/static\//.test(all)) out.push("Next.js");
  if (/\/assets\/index-[A-Za-z0-9_-]+\.js/.test(all) || /__vite/i.test(all)) out.push("Vite");
  if (/gptengineer\.js|lovable-tagger|lovable\.app|lovableproject\.com/i.test(all)) out.push("Lovable");
  if (/bolt\.new|stackblitz/i.test(all)) out.push("Bolt");
  if (/base44/i.test(all)) out.push("Base44");
  if (/replit/i.test(html)) out.push("Replit");
  if (/framerusercontent\.com/i.test(html)) out.push("Framer");
  if (/webflow/i.test(html)) out.push("Webflow");
  return [...new Set(out)];
}

function detectStack(texts: string[], html: string, scriptUrls: string[]): DetectedStack {
  const all = texts.join("\n");
  const stack: DetectedStack = { frameworks: detectFrameworks(html, scriptUrls) };
  const sbUrl = all.match(/https:\/\/([a-z0-9]{20})\.supabase\.co/);
  const anon = [...all.matchAll(/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g)].some(
    (m) => decodeJwtPayload(m[0])?.role === "anon",
  );
  const publishable = /\bsb_publishable_[A-Za-z0-9_-]{20,}/.test(all);
  if (sbUrl || anon || publishable) {
    stack.supabase = { url: sbUrl?.[0], projectRef: sbUrl?.[1], anonKeyFound: anon || publishable };
  }
  const fb = all.match(/["']?projectId["']?\s*:\s*["']([a-z0-9-]{4,})["']/);
  if (/firebaseapp\.com|firebaseio\.com|firebasestorage\.app/.test(all) || (fb && /AIza[0-9A-Za-z_-]{35}/.test(all))) {
    stack.firebase = { projectId: fb?.[1] };
  }
  if (/\bpk_(live|test)_[A-Za-z0-9]{24,}/.test(all)) stack.stripe = { publishableKeyFound: true };
  return stack;
}

function anonKey(texts: string[]): string | null {
  for (const t of texts) {
    for (const m of t.matchAll(/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g)) {
      if (decodeJwtPayload(m[0])?.role === "anon") return m[0];
    }
    const pub = t.match(/\bsb_publishable_[A-Za-z0-9_-]{20,}/);
    if (pub) return pub[0];
  }
  return null;
}

export async function scanUrl(input: string, options: ScanOptions = {}): Promise<Report | { error: string }> {
  const target = parseTarget(input);
  if (!target.ok) return { error: target.error };
  const fetcher = options.fetch ?? fetch;
  const maxBytes = options.maxBytes ?? 3_000_000;
  const maxScripts = options.maxScripts ?? 25;
  const maxSourceMaps = options.maxSourceMaps ?? 5;
  const budget: Budget = {
    deadline: Date.now() + (options.totalTimeoutMs ?? 30_000),
    bytesLeft: options.maxTotalBytes ?? 25_000_000,
    timeoutMs: options.timeoutMs ?? 10_000,
  };
  const warnings: string[] = [];
  const findings: Finding[] = [];
  const outOfBudget = () => budget.deadline - Date.now() <= 0 || budget.bytesLeft <= 0;

  const page = await get(fetcher, target.url.toString(), budget, { maxBytes: 2_000_000 });
  if (!page) return { error: "The site did not respond. Check the address and that the app is deployed." };
  if (page.status >= 400) return { error: `The site answered with status ${page.status}.` };

  const { external, inline } = extractScripts(page.body, page.url);
  const queue = external.filter((u) => sameSite(u, page.url));
  const skipped = external.length - queue.length;
  const seen = new Set<string>();
  const texts: { source: string; body: string }[] = [{ source: page.url, body: page.body }];
  inline.forEach((body, i) => texts.push({ source: `${page.url} (inline script ${i + 1})`, body }));
  const maps: string[] = [];

  while (queue.length && seen.size < maxScripts && !outOfBudget()) {
    const next = queue.shift()!;
    if (seen.has(next)) continue;
    seen.add(next);
    const res = await get(fetcher, next, budget, { maxBytes });
    if (!res || res.status >= 400) continue;
    if (res.truncated) warnings.push(`${next} is larger than ${Math.round(maxBytes / 1_000_000)} MB; only the first part was checked.`);
    texts.push({ source: res.url, body: res.body });
    for (const c of chunkReferences(res.body, page.url)) if (!seen.has(c) && sameSite(c, page.url)) queue.push(c);
    const map = res.body.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/m)?.[1];
    if (map && !map.startsWith("data:")) {
      try {
        maps.push(new URL(map, res.url).toString());
      } catch {}
    } else if (!map && /\.js$/.test(new URL(res.url).pathname)) {
      maps.push(`${res.url}.map`);
    }
  }
  if (queue.length && seen.size >= maxScripts) warnings.push(`The app loads more than ${maxScripts} scripts; the first ${maxScripts} were checked.`);
  if (skipped) warnings.push(`${skipped} script${skipped === 1 ? "" : "s"} from other domains were not checked.`);

  let exposedMaps = 0;
  for (const mapUrl of maps.slice(0, maxSourceMaps * 2)) {
    if (exposedMaps >= maxSourceMaps || outOfBudget()) break;
    const res = await get(fetcher, mapUrl, budget, { maxBytes });
    if (!res || res.status !== 200 || !/^\s*\{/.test(res.body)) continue;
    if (!/"(sources|mappings)"\s*:/.test(res.body.slice(0, 5000)) && !/"sources"\s*:/.test(res.body)) continue;
    exposedMaps += 1;
    texts.push({ source: mapUrl, body: res.body });
    if (exposedMaps === 1) {
      findings.push({
        rule: "SRC-01",
        severity: "medium",
        object: new URL(mapUrl).pathname,
        title: "Source maps are public",
        detail: "Source maps let any visitor read the original source code, including comments, internal routes and logic that is easier to attack once readable.",
        remedy: "Turn off production source maps (Vite: build.sourcemap = false; Next.js: productionBrowserSourceMaps = false) or upload them to your error tracker instead of serving them.",
      });
    }
  }

  const hits: SecretHit[] = [];
  for (const t of texts) hits.push(...findSecrets(t.body, t.source));
  const byValue = new Map<string, SecretHit[]>();
  for (const h of hits) {
    const key = `${h.pattern.id}:${h.value}`;
    if (!byValue.has(key)) byValue.set(key, []);
    byValue.get(key)!.push(h);
  }
  for (const group of byValue.values()) {
    const h = group[0];
    const sources = [...new Set(group.map((g) => g.source))];
    findings.push({
      rule: h.pattern.id,
      severity: h.pattern.severity,
      object: new URL(sources[0].replace(/ \(inline script \d+\)$/, "")).pathname || "/",
      title: `${h.pattern.name} in the front end`,
      detail: `Found in ${sources.length === 1 ? sources[0] : `${sources.length} files, first ${sources[0]}`}. Every visitor downloads this file.`,
      remedy: h.pattern.remedy,
      evidence: redact(h.value),
    });
  }

  const origin = new URL(page.url).origin;
  const fileHits = new Set<string>();
  for (const f of EXPOSED_FILES) {
    if (fileHits.has(f.id) || outOfBudget()) continue;
    const res = await get(fetcher, `${origin}${f.path}`, budget, { maxBytes: 200_000 });
    if (!res || res.status !== 200 || /text\/html/i.test(res.contentType) || !f.test(res.body)) continue;
    fileHits.add(f.id);
    const secretsInside = findSecrets(res.body, `${origin}${f.path}`);
    findings.push({
      rule: f.id,
      severity: f.severity,
      object: f.path,
      title: f.title,
      detail:
        f.id === "FILE-ENV"
          ? `${origin}${f.path} returns an environment file${secretsInside.length ? ` with ${secretsInside.length} recognised secret${secretsInside.length === 1 ? "" : "s"}` : ""}. Treat every value in it as leaked.`
          : `${origin}${f.path} is readable. The full source history, including deleted secrets, can be downloaded from it.`,
      remedy:
        f.id === "FILE-ENV"
          ? "Remove the file from the deployed folder, rotate every key it contains, and block dotfiles at the host."
          : "Deploy the build output only, not the repository folder, and block /.git at the host.",
    });
  }

  if (outOfBudget()) warnings.push("The scan stopped at its time or size limit; some scripts and files were not checked.");

  const allTexts = texts.map((t) => t.body);
  const stack = detectStack(allTexts, page.body, [...seen]);
  const next: string[] = [];

  if (stack.supabase) {
    next.push(
      `Supabase${stack.supabase.projectRef ? ` project ${stack.supabase.projectRef}` : ""} found. The anon key in the front end is public by design; what it can reach depends on RLS. Run the inventory query in the SQL Editor for the full database check.`,
    );
    if (options.probeSupabase && stack.supabase.url && !outOfBudget()) {
      const key = anonKey(allTexts);
      if (key) {
        const res = await get(fetcher, `${stack.supabase.url}/rest/v1/`, budget, {
          maxBytes: 2_000_000,
          headers: { apikey: key, authorization: `Bearer ${key}`, accept: "application/openapi+json" },
        });
        if (res && res.status === 200) {
          try {
            const spec = JSON.parse(res.body) as { paths?: Record<string, unknown> };
            const paths = Object.keys(spec.paths ?? {}).filter((p) => p !== "/");
            const tables = paths.filter((p) => !p.startsWith("/rpc/")).map((p) => p.slice(1));
            const rpc = paths.filter((p) => p.startsWith("/rpc/")).map((p) => p.slice(5));
            if (tables.length || rpc.length) {
              findings.push({
                rule: "SUPA-01",
                severity: "info",
                object: stack.supabase.url,
                title: "Objects reachable with the anon key",
                detail: `The API lists ${tables.length} table${tables.length === 1 ? "" : "s"} or view${tables.length === 1 ? "" : "s"}${tables.length ? ` (${tables.slice(0, 12).join(", ")}${tables.length > 12 ? ", …" : ""})` : ""} and ${rpc.length} function${rpc.length === 1 ? "" : "s"} to anyone with the public key. Whether rows come back depends on RLS; no rows were read.`,
                remedy: "Run the inventory query to see which of these have RLS off or open policies.",
              });
            }
          } catch {}
        } else if (res && res.status === 401) {
          next.push("The schema listing is closed to the anon key, which is good practice.");
        }
      }
    }
  }
  if (stack.firebase) {
    next.push(`Firebase${stack.firebase.projectId ? ` project ${stack.firebase.projectId}` : ""} found. The Firebase web config is public by design; access is decided by Firestore and Storage security rules, which this check does not see.`);
  }

  return {
    engine: "url",
    findings: sortFindings(findings),
    summary: summarise(findings),
    notChecked: [
      "Database access rules: RLS policies in Supabase, security rules in Firebase.",
      "Server routes, edge functions and webhooks.",
      "Pages behind sign-in, and scripts loaded only after sign-in.",
      "Scripts served from other domains.",
    ],
    stack,
    next,
    warnings,
  };
}
