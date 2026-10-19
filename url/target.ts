export type TargetResult = { ok: true; url: URL } | { ok: false; error: string };

const BLOCKED_HOSTS = /(^|\.)(localhost|local|internal|intranet|lan|home|corp|localdomain|onion|arpa)$/i;

function ipv4(host: string): number[] | null {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((p) => p >= 0 && p <= 255) ? parts : null;
}

export function isPrivateIPv4([a, b, c]: number[]): boolean {
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function expandIPv6(host: string): string[] | null {
  const parts = host.split("::");
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(":") : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  const last = tail.length ? tail[tail.length - 1] : head[head.length - 1];
  if (last && last.includes(".")) {
    const v4 = ipv4(last);
    if (!v4) return null;
    const words = [((v4[0] << 8) | v4[1]).toString(16), ((v4[2] << 8) | v4[3]).toString(16)];
    if (tail.length) tail.splice(tail.length - 1, 1, ...words);
    else head.splice(head.length - 1, 1, ...words);
  }
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (parts.length === 1 && missing !== 0)) return null;
  const full = [...head, ...Array(parts.length === 2 ? missing : 0).fill("0"), ...tail];
  if (full.length !== 8 || full.some((w) => !/^[0-9a-f]{1,4}$/i.test(w))) return null;
  return full.map((w) => w.toLowerCase().padStart(4, "0"));
}

export function isPrivateIPv6(host: string): boolean {
  const words = expandIPv6(host);
  if (!words) return true;
  const n = words.map((w) => parseInt(w, 16));
  if (n.slice(0, 7).every((w) => w === 0) && (n[7] === 0 || n[7] === 1)) return true;
  if (n.slice(0, 5).every((w) => w === 0) && n[5] === 0xffff) return isPrivateIPv4([n[6] >> 8, n[6] & 0xff, n[7] >> 8, n[7] & 0xff]);
  if (n[0] === 0x64 && n[1] === 0xff9b) return isPrivateIPv4([n[6] >> 8, n[6] & 0xff, n[7] >> 8, n[7] & 0xff]);
  if ((n[0] & 0xfe00) === 0xfc00) return true;
  if ((n[0] & 0xffc0) === 0xfe80) return true;
  if ((n[0] & 0xff00) === 0xff00) return true;
  if (n[0] === 0x2001 && n[1] === 0) return true;
  if (n[0] === 0x0100 && n[1] === 0 && n[2] === 0 && n[3] === 0) return true;
  return false;
}

export function checkHost(hostname: string): string | null {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.+$/, "");
  if (!host) return "The address has no host name.";
  if (BLOCKED_HOSTS.test(host)) return "Local and internal addresses cannot be checked.";
  const v4 = ipv4(host);
  if (v4) return isPrivateIPv4(v4) ? "Private network addresses cannot be checked." : null;
  if (host.includes(":")) return isPrivateIPv6(host) ? "Private network addresses cannot be checked." : null;
  if (!host.includes(".")) return "Enter a public address, for example https://example.com.";
  return null;
}

export function parseTarget(input: string): TargetResult {
  let raw = input.trim();
  if (!raw) return { ok: false, error: "Enter the address of your app." };
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, error: "This is not a valid address." };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return { ok: false, error: "Only http and https addresses can be checked." };
  if (url.username || url.password) return { ok: false, error: "Remove the login details from the address." };
  if (url.port && url.port !== "80" && url.port !== "443") return { ok: false, error: "Only standard ports 80 and 443 can be checked." };
  const blocked = checkHost(url.hostname);
  if (blocked) return { ok: false, error: blocked };
  url.hostname = url.hostname.replace(/\.+$/, "");
  url.hash = "";
  return { ok: true, url };
}
