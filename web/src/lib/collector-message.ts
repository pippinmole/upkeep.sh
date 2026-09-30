// Helpers for showing a collector's `error` string (free text from the
// agent) on the host page: sentence casing, a short summary with the rest
// behind a toggle, and `backtick` spans rendered as code.

// Capitalizes the first letter when the message starts with a plain
// lowercase word ("host unix sockets …"), but leaves paths and identifiers
// alone ("etc/machine-id is empty", "dpkg-query: …").
export function sentenceCase(msg: string): string {
  return /^[a-z]+(?=[\s,:;]|$)/.test(msg) ? msg[0].toUpperCase() + msg.slice(1) : msg;
}

// Splits a message after its first sentence: a ". " followed by an
// uppercase letter, outside backticks and parentheses. `rest` is empty when
// the message is a single sentence.
export function splitFirstSentence(msg: string): { summary: string; rest: string } {
  let inCode = false;
  let depth = 0;
  for (let i = 0; i < msg.length - 2; i++) {
    const c = msg[i];
    if (c === "`") inCode = !inCode;
    else if (inCode) continue;
    else if (c === "(") depth++;
    else if (c === ")") depth = Math.max(0, depth - 1);
    else if (c === "." && depth === 0 && /\s/.test(msg[i + 1])) {
      const rest = msg.slice(i + 1).trimStart();
      if (/^[A-Z]/.test(rest)) return { summary: msg.slice(0, i + 1), rest };
    }
  }
  return { summary: msg, rest: "" };
}

export type MessageSegment = { code: boolean; text: string };

// Splits on backticks: odd segments are code. An unmatched trailing
// backtick is kept as literal text.
export function inlineCodeSegments(text: string): MessageSegment[] {
  const parts = text.split("`");
  if (parts.length % 2 === 0) {
    const last = parts.pop()!;
    parts[parts.length - 1] += "`" + last;
  }
  return parts.map((t, i) => ({ code: i % 2 === 1, text: t })).filter((s) => s.text !== "");
}
