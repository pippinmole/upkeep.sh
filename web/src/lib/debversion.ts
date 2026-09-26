// dpkg version ordering (`dpkg --compare-versions`), a port of
// server/internal/debversion's Compare for the dashboard's History tab
// (upgrade vs downgrade). The Go package is authoritative: the matcher
// never uses this, and this file is checked against the same dpkg vectors
// (server/internal/debversion/testdata/dpkg_compare_vectors.txt).
//
// Works on UTF-8 bytes like dpkg does. Returns null for versions dpkg
// rejects outright (the caller then falls back to "changed").

type Version = { epoch: number; upstream: Uint8Array; revision: Uint8Array };

const enc = new TextEncoder();
const MAX_EPOCH = 2147483647;

const isDigit = (c: number) => c >= 0x30 && c <= 0x39;
const isAlpha = (c: number) => (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);

function parseEpoch(s: string): number | null {
  let digits = s;
  let neg = false;
  if (digits[0] === "+" || digits[0] === "-") {
    neg = digits[0] === "-";
    digits = digits.slice(1);
  }
  if (!/^\d+$/.test(digits)) return null;
  digits = digits.replace(/^0+/, "");
  if (digits.length > 10) return null;
  const val = digits === "" ? 0 : Number(digits);
  if (val > MAX_EPOCH || (neg && val !== 0)) return null;
  return val;
}

export function parseDebVersion(input: string): Version | null {
  const s = input.replace(/^[ \t]+/, "").replace(/[ \t]+$/, "");
  if (s === "" || /[ \t]/.test(s)) return null;
  let rest = s;
  let epoch = 0;
  const colon = rest.indexOf(":");
  if (colon >= 0) {
    const e = parseEpoch(rest.slice(0, colon));
    if (e === null || colon + 1 === rest.length) return null;
    epoch = e;
    rest = rest.slice(colon + 1);
  }
  let upstream = rest;
  let revision = "";
  const hyphen = rest.lastIndexOf("-");
  if (hyphen >= 0) {
    upstream = rest.slice(0, hyphen);
    revision = rest.slice(hyphen + 1);
    if (revision === "") return null;
  }
  if (upstream === "") return null;
  return { epoch, upstream: enc.encode(upstream), revision: enc.encode(revision) };
}

function order(c: number): number {
  if (isDigit(c)) return 0;
  if (isAlpha(c)) return c;
  if (c === 0x7e) return -1; // '~'
  if (c >= 0x80) return ((c << 24) >> 24) + 256; // signed char, as dpkg
  return c + 256;
}

function verrevcmp(a: Uint8Array, b: Uint8Array): number {
  let i = 0;
  let j = 0;
  const weight = (s: Uint8Array, k: number) => (k < s.length ? order(s[k]) : 0);
  while (i < a.length || j < b.length) {
    while ((i < a.length && !isDigit(a[i])) || (j < b.length && !isDigit(b[j]))) {
      const ac = weight(a, i);
      const bc = weight(b, j);
      if (ac !== bc) return Math.sign(ac - bc);
      i++;
      j++;
    }
    while (i < a.length && a[i] === 0x30) i++;
    while (j < b.length && b[j] === 0x30) j++;
    let firstDiff = 0;
    while (i < a.length && j < b.length && isDigit(a[i]) && isDigit(b[j])) {
      if (firstDiff === 0) firstDiff = a[i] - b[j];
      i++;
      j++;
    }
    if (i < a.length && isDigit(a[i])) return 1;
    if (j < b.length && isDigit(b[j])) return -1;
    if (firstDiff !== 0) return Math.sign(firstDiff);
  }
  return 0;
}

// -1 / 0 / 1 like dpkg; null when either version is unparseable.
export function compareDebVersions(a: string, b: string): -1 | 0 | 1 | null {
  const va = parseDebVersion(a);
  const vb = parseDebVersion(b);
  if (!va || !vb) return null;
  if (va.epoch !== vb.epoch) return va.epoch < vb.epoch ? -1 : 1;
  const c = verrevcmp(va.upstream, vb.upstream) || verrevcmp(va.revision, vb.revision);
  return c < 0 ? -1 : c > 0 ? 1 : 0;
}
