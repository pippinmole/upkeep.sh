// The avatar's initials: the first letters of the first and last words of
// the name ("Jonathan Ruffles" → "JR"), or the first two letters of a
// one-word name or, with no name, of the email ("jonny@…" → "JO").
export function initialsFor({ name, email }: { name: string; email: string }): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  const first = words[0];
  const last = words.at(-1);
  if (words.length >= 2 && first && last) {
    return (first.charAt(0) + last.charAt(0)).toUpperCase();
  }
  return (first ?? email).slice(0, 2).toUpperCase();
}
