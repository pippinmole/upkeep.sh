import { isRole, type Role } from "@/lib/roles";

// Input checks for Settings > Members, shared by the dialogs and the server
// actions (which always re-run them). Mirrors Better Auth's limits: the
// username plugin's 3-30 characters of letters, digits, underscores and
// dots, and the 8-character minimum password (lib/auth.ts).

export const USERNAME_PATTERN = /^[a-zA-Z0-9_.]{3,30}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export const MIN_PASSWORD = 8;
const MAX_PASSWORD = 128;

export const MEMBER_ERRORS = {
  notFound: "That account no longer exists. Reload the page.",
  self: "You can't change your own account here. Ask another administrator.",
  lastAdmin: "The install needs at least one enabled administrator.",
  signUp: {
    USERNAME_IS_ALREADY_TAKEN: "That username is taken.",
    USER_ALREADY_EXISTS: "An account with that email already exists.",
    USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL: "An account with that email already exists.",
    INVALID_USERNAME: "Usernames can only contain letters, numbers, underscores and dots.",
    USERNAME_TOO_SHORT: "Use at least 3 characters for the username.",
    USERNAME_TOO_LONG: "Use at most 30 characters for the username.",
    INVALID_EMAIL: "Enter a valid email address.",
    PASSWORD_TOO_SHORT: "Use at least 8 characters for the password.",
    PASSWORD_TOO_LONG: "That password is too long.",
  } as Partial<Record<string, string>>,
};

export function validatePassword(password: unknown): string | null {
  if (typeof password !== "string" || password.length < MIN_PASSWORD) {
    return `Use at least ${MIN_PASSWORD} characters.`;
  }
  if (password.length > MAX_PASSWORD) return "That password is too long.";
  return null;
}

export type CleanMember = {
  username: string;
  email: string;
  name: string;
  role: Role;
  password: string;
};

export function validateNewMember(input: unknown): {
  member: CleanMember | null;
  fieldErrors: Record<string, string>;
} {
  const v = (input ?? {}) as Record<string, unknown>;
  const str = (k: string) => (typeof v[k] === "string" ? (v[k] as string).trim() : "");
  const username = str("username");
  const email = str("email").toLowerCase();
  const name = str("name").slice(0, 100);
  const role = v.role;
  const password = typeof v.password === "string" ? v.password : "";

  const fieldErrors: Record<string, string> = {};
  if (!USERNAME_PATTERN.test(username)) {
    fieldErrors.username = "3 to 30 characters: letters, numbers, underscores and dots.";
  }
  if (!EMAIL_PATTERN.test(email) || email.length > 254) {
    fieldErrors.email = "Enter a valid email address.";
  }
  if (!isRole(role)) fieldErrors.role = "Pick a role.";
  const pw = validatePassword(password);
  if (pw) fieldErrors.password = pw;

  if (Object.keys(fieldErrors).length > 0) return { member: null, fieldErrors };
  return { member: { username, email, name, role: role as Role, password }, fieldErrors };
}

// A readable temporary password for the "Generate" button: 16 characters
// from an alphabet without look-alikes (no 0/O, 1/l/I).
const ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
export function generateTemporaryPassword(length = 16): string {
  const bytes = new Uint32Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]).join("");
}
