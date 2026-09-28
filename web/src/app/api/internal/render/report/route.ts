// Internal: renders a report email for the Go worker, which POSTs the stored
// snapshot here and sends the result over SMTP (docs/decisions/
// report-email-html.md). Not part of the public site:
//
//   - SW_INTERNAL_RENDER_SECRET unset or empty -> 404 (feature off).
//   - Only answered on the internal host: the request's Host must be the
//     host of SW_WEB_INTERNAL_URL (the same variable the worker uses, e.g.
//     http://web:3000 on the compose network), and an X-Forwarded-Host, which
//     the public reverse proxy adds, must match it too. Anything else -> 404,
//     so the route doesn't exist as far as the public domain is concerned.
//     If SW_WEB_INTERNAL_URL is unset or names the public host (NEXTAUTH_URL /
//     AUTH_URL), nothing is accepted.
//   - Authorization: Bearer <secret>, compared in constant time -> 401.
//   - Body {"snapshot": <ReportSnapshot>, "report_url": string | null} -> 400
//     when malformed; render errors -> 500, which the worker retries.
//
// proxy.ts only guards /dashboard, so this path never redirects to login.
// Never log the secret or the snapshot.

import { createHash, timingSafeEqual } from "crypto";
import { renderReportEmail } from "@/emails/render-report";
import { REPORT_SCHEMA_VERSION, type ReportSnapshot } from "@/lib/report-snapshot";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function notFound() {
  return new Response("Not Found", { status: 404 });
}

function hostOf(url: string | undefined): URL | null {
  if (!url) return null;
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

// A Host header value normalised like URL.host (lower case, default port
// dropped) under the internal URL's scheme.
function normaliseHost(value: string, protocol: string): string | null {
  try {
    return new URL(`${protocol}//${value.trim()}`).host;
  } catch {
    return null;
  }
}

function onInternalHost(request: Request): boolean {
  const internal = hostOf(process.env.SW_WEB_INTERNAL_URL);
  if (!internal) return false;
  const publicHosts = [process.env.NEXTAUTH_URL, process.env.AUTH_URL]
    .map((u) => hostOf(u)?.host)
    .filter(Boolean);
  if (publicHosts.includes(internal.host)) return false;

  const host = request.headers.get("host");
  if (!host || normaliseHost(host, internal.protocol) !== internal.host) return false;
  const forwarded = request.headers.get("x-forwarded-host");
  if (forwarded !== null) {
    // A proxy may append: "a, b". Every hop must be the internal host.
    const hops = forwarded.split(",").map((h) => normaliseHost(h, internal.protocol));
    if (hops.some((h) => h !== internal.host)) return false;
  }
  return true;
}

// SHA-256 first so both sides have the same length, as timingSafeEqual needs.
function secretMatches(header: string | null, secret: string): boolean {
  const presented = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  const a = createHash("sha256").update(presented).digest();
  const b = createHash("sha256").update(secret).digest();
  return timingSafeEqual(a, b) && presented !== "";
}

type RenderRequest = { snapshot: ReportSnapshot; report_url: string | null };

// Minimal shape check: the snapshot is ours (written by the worker), so only
// what would make the render meaningless is refused here.
function parseBody(body: unknown): RenderRequest | null {
  if (typeof body !== "object" || body === null) return null;
  const { snapshot, report_url } = body as Record<string, unknown>;
  if (typeof snapshot !== "object" || snapshot === null) return null;
  if ((snapshot as { schema_version?: unknown }).schema_version !== REPORT_SCHEMA_VERSION) {
    return null;
  }
  if (report_url !== null) {
    if (typeof report_url !== "string") return null;
    const u = hostOf(report_url);
    if (!u || (u.protocol !== "http:" && u.protocol !== "https:")) return null;
  }
  return { snapshot: snapshot as ReportSnapshot, report_url };
}

export async function POST(request: Request): Promise<Response> {
  const secret = process.env.SW_INTERNAL_RENDER_SECRET;
  if (!secret) return notFound();
  if (!onInternalHost(request)) return notFound();
  if (!secretMatches(request.headers.get("authorization"), secret)) {
    return new Response("Unauthorized", { status: 401 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return new Response("Bad Request: body is not JSON", { status: 400 });
  }
  const req = parseBody(body);
  if (!req) {
    return new Response(
      `Bad Request: want {"snapshot": {"schema_version": ${REPORT_SCHEMA_VERSION}, ...}, "report_url": string | null}`,
      { status: 400 },
    );
  }

  try {
    return Response.json(await renderReportEmail(req.snapshot, req.report_url));
  } catch (err) {
    console.error(
      "render report email (report schedule %s): %s",
      req.snapshot.schedule?.id ?? "unknown",
      err instanceof Error ? err.message : String(err),
    );
    return new Response("Internal Server Error: render failed", { status: 500 });
  }
}
