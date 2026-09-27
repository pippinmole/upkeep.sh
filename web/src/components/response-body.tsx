"use client";

import hljs from "highlight.js/lib/core";
import json from "highlight.js/lib/languages/json";
import xml from "highlight.js/lib/languages/xml";
import { html as beautifyHtml, js as beautifyJs } from "js-beautify";

hljs.registerLanguage("json", json);
hljs.registerLanguage("xml", xml);

type Kind = "json" | "html" | "text";

// The server caps stored errors at 500 bytes and marks the cut with "…", so
// bodies are often truncated mid-document: JSON that no longer parses is still
// re-indented by the JS beautifier, which tolerates unterminated input.
function format(body: string): { kind: Kind; text: string } {
  const trimmed = body.trim();
  if (/^[[{]/.test(trimmed)) {
    try {
      return { kind: "json", text: JSON.stringify(JSON.parse(trimmed), null, 2) };
    } catch {
      return { kind: "json", text: beautifyJs(trimmed, { indent_size: 2 }) };
    }
  }
  if (trimmed.startsWith("<")) {
    return { kind: "html", text: beautifyHtml(trimmed, { indent_size: 2, wrap_line_length: 0 }) };
  }
  return { kind: "text", text: body };
}

// Splits a delivery error like "HTTP 404: <body>" into the message and the
// response body the worker appended to it.
function splitDeliveryError(error: string): { message: string; body: string | null } {
  const m = /^(HTTP \d{3}[^:]*): ([\s\S]+)$/.exec(error);
  return m ? { message: m[1], body: m[2] } : { message: error, body: null };
}

const KIND_LABEL: Record<Kind, string> = { json: "JSON", html: "HTML", text: "Text" };

export function ResponseBody({ body, defaultOpen }: { body: string; defaultOpen?: boolean }) {
  const truncated = body.endsWith("…");
  const { kind, text } = format(truncated ? body.slice(0, -1) : body);
  return (
    <details open={defaultOpen}>
      <summary className="text-muted-foreground hover:text-foreground cursor-pointer text-xs select-none">
        Response body ({KIND_LABEL[kind]}
        {truncated && ", truncated"})
      </summary>
      <pre className="bg-muted mt-1.5 max-h-80 max-w-3xl overflow-auto rounded-md p-3 font-mono text-xs leading-relaxed whitespace-pre">
        {kind === "text" ? (
          <code>{text}</code>
        ) : (
          // hljs escapes the input, so the untrusted response body can't inject markup.
          <code
            className="hljs"
            dangerouslySetInnerHTML={{
              __html: hljs.highlight(text, { language: kind === "json" ? "json" : "xml" }).value,
            }}
          />
        )}
        {truncated && <span className="text-muted-foreground">{"\n"}…</span>}
      </pre>
    </details>
  );
}

// A delivery error: the message, plus the formatted response body if the
// receiver sent one.
export function DeliveryError({ error, defaultOpen }: { error: string; defaultOpen?: boolean }) {
  const { message, body } = splitDeliveryError(error);
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <span className="font-mono text-xs break-all">{message}</span>
      {body && <ResponseBody body={body} defaultOpen={defaultOpen} />}
    </div>
  );
}
