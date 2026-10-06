import { z } from "zod";

// The Create API token form (docs/MCP.md#api-tokens-headless-agents), shared
// by the dialog and the server action so both check the same thing.
// "Never" is allowed: a headless agent breaks silently when its token
// expires, and the list shows last use so stale tokens are easy to spot.

export const TOKEN_EXPIRIES = [
  { value: "30", label: "30 days", days: 30 },
  { value: "90", label: "90 days", days: 90 },
  { value: "365", label: "1 year", days: 365 },
  { value: "never", label: "Never", days: null },
] as const;

export type TokenExpiry = (typeof TOKEN_EXPIRIES)[number]["value"];

export const DEFAULT_TOKEN_EXPIRY: TokenExpiry = "90";

// lib/auth.ts allows the plugin the same maximum.
export const TOKEN_NAME_MAX = 64;

export const newTokenSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, "Name the token after what will use it.")
    .max(TOKEN_NAME_MAX, `At most ${TOKEN_NAME_MAX} characters.`),
  expiry: z.enum(["30", "90", "365", "never"], { message: "Choose an expiry." }),
});

export type NewToken = z.infer<typeof newTokenSchema>;

// The expiry in seconds for the plugin's expiresIn, or null for never.
export function expiresInSeconds(expiry: TokenExpiry): number | null {
  const days = TOKEN_EXPIRIES.find((e) => e.value === expiry)?.days ?? null;
  return days === null ? null : days * 24 * 60 * 60;
}
