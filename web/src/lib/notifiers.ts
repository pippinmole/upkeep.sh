// Notification channel types, as declared by the Go registry
// (server/internal/notify). notifier-types.json is generated from it
// (`go test ./internal/notify/notifiers -update`, checked by a golden
// test), so the dashboard renders channel forms and validates input from
// the same declaration the worker delivers with. Adding a channel type
// needs no change here.
import schema from "./notifier-types.json";

export type FieldType = "text" | "url" | "email" | "secret" | "select" | "bool";

export type ChannelField = {
  key: string;
  label: string;
  type: FieldType;
  help?: string;
  placeholder?: string;
  required?: boolean;
  secret?: boolean; // stored in notification_channels.secrets; write-only
  generated?: boolean; // created by the server, shown once
  maxLength?: number;
  options?: { value: string; label: string }[];
};

export type ChannelType = {
  type: string;
  label: string;
  description: string;
  fields: ChannelField[];
};

export const CHANNEL_TYPES = schema.types as ChannelType[];

export function channelType(type: string): ChannelType | undefined {
  return CHANNEL_TYPES.find((t) => t.type === type);
}

export const EVENT_TYPES = schema.eventTypes as string[];

export const EVENT_TYPE_LABEL: Record<string, string> = {
  "finding.opened": "Finding opened",
  "finding.reopened": "Finding reopened",
  "finding.resolved": "Finding resolved",
  "agent.stale": "Agent went stale",
  "agent.recovered": "Agent came back",
};

export function eventTypeLabel(t: string): string {
  return EVENT_TYPE_LABEL[t] ?? t;
}

export const isFindingEvent = (t: string) => t.startsWith("finding.");

// Rule option choices (seconds). Bounds match the alert_rules CHECKs.
export const DEDUP_WINDOWS = [0, 900, 3600, 6 * 3600, 86400, 7 * 86400];
export const DIGEST_INTERVALS = [900, 3600, 6 * 3600, 86400, 7 * 86400];

export function durationLabel(seconds: number): string {
  if (seconds === 0) return "Off";
  if (seconds % 86400 === 0) return seconds === 86400 ? "1 day" : `${seconds / 86400} days`;
  if (seconds % 3600 === 0) return seconds === 3600 ? "1 hour" : `${seconds / 3600} hours`;
  return `${Math.round(seconds / 60)} minutes`;
}

// findings.severity_rank values (server/internal/severity buckets).
export const SEVERITY_FLOORS = [
  { rank: 0, label: "Any severity" },
  { rank: 2, label: "Low and above" },
  { rank: 3, label: "Unknown and above" },
  { rank: 4, label: "Medium and above" },
  { rank: 5, label: "High and above" },
  { rank: 6, label: "Critical only" },
];

// Mirrors server/internal/netguard's URL shape rules (https, ports 443 /
// 8443, no credentials, no literal private address). The worker re-checks
// every delivery after DNS resolution; this only gives early feedback.
// SW_NOTIFY_ALLOW_PRIVATE_NETWORKS relaxes both sides (dev only).
function checkUrl(raw: string, allowPrivate: boolean): string | null {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return "is not a valid URL";
  }
  if (u.protocol !== "https:" && !(allowPrivate && u.protocol === "http:")) {
    return "must use https";
  }
  if (u.username || u.password) return "must not contain credentials";
  if (allowPrivate) return null;
  if (u.port && u.port !== "443" && u.port !== "8443") return "must use port 443 or 8443";
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    /^(127|10|0)\./.test(host) ||
    /^169\.254\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host) ||
    host === "::1" ||
    host === "::" ||
    /^(fc|fd|fe8|fe9|fea|feb)/.test(host) ||
    host.startsWith("::ffff:")
  ) {
    return "must be a public address";
  }
  return null;
}

export type ValidatedConfig = {
  config: Record<string, string>; // non-secret fields
  secrets: Record<string, string>; // user-entered secret fields that were set
  errors: Record<string, string>;
};

// Validates submitted values against a channel type's fields. Generated
// secrets are never taken from input. Blank user-entered secrets are left
// out (on edit: "keep the current value"); `existingSecrets` lists the ones
// already stored, which satisfy `required`.
export function validateChannelValues(
  spec: ChannelType,
  values: Record<string, unknown>,
  opts: { allowPrivate: boolean; existingSecrets?: string[] },
): ValidatedConfig {
  const out: ValidatedConfig = { config: {}, secrets: {}, errors: {} };
  for (const f of spec.fields) {
    if (f.generated) continue;
    const raw = values[f.key];
    let v = typeof raw === "string" ? raw.trim() : typeof raw === "boolean" ? String(raw) : "";
    if (f.type === "bool") v = v === "true" ? "true" : "false";
    if (!v) {
      const kept = f.secret && opts.existingSecrets?.includes(f.key);
      if (f.required && !kept) out.errors[f.key] = `${f.label} is required`;
      continue;
    }
    if (f.maxLength && v.length > f.maxLength) {
      out.errors[f.key] = `${f.label} is longer than ${f.maxLength} characters`;
      continue;
    }
    if (f.type === "url") {
      const err = checkUrl(v, opts.allowPrivate);
      if (err) {
        out.errors[f.key] = `${f.label} ${err}`;
        continue;
      }
    }
    if (f.type === "email" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) {
      out.errors[f.key] = `${f.label} is not a valid email address`;
      continue;
    }
    if (f.type === "select" && !f.options?.some((o) => o.value === v)) {
      out.errors[f.key] = `${f.label}: invalid choice`;
      continue;
    }
    if (f.secret) out.secrets[f.key] = v;
    else out.config[f.key] = v;
  }
  return out;
}

// A short, non-secret description of where a channel delivers (its first
// non-secret field), for tables.
export function channelTarget(type: string, config: Record<string, string>): string {
  const spec = channelType(type);
  const f = spec?.fields.find((f) => !f.secret && config[f.key]);
  return f ? config[f.key] : "";
}
