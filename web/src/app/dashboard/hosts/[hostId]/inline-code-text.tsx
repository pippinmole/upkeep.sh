import { inlineCodeSegments } from "@/lib/collector-message";

// Plain text with `backtick` spans rendered as <code>.
export function InlineCodeText({ text }: { text: string }) {
  return (
    <>
      {inlineCodeSegments(text).map((s, i) =>
        s.code ? (
          <code
            key={i}
            className="bg-muted text-foreground rounded px-1 py-0.5 font-mono text-[0.8125rem]"
          >
            {s.text}
          </code>
        ) : (
          <span key={i}>{s.text}</span>
        ),
      )}
    </>
  );
}
