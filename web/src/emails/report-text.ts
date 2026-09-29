// Plain-text part of the report email: the same model as report.tsx, laid
// out for a terminal-width reader rather than converted from the HTML
// (tables don't survive html-to-text well).

import { moreLine, type ReportEmailModel } from "./report-content";

export function reportEmailText(m: ReportEmailModel): string {
  const out: string[] = [];
  const heading = (text: string) => out.push("", text, "-".repeat(text.length));

  out.push(m.title, "=".repeat(m.title.length), m.period);
  if (m.reportUrl) out.push(`Full report: ${m.reportUrl}`);

  heading("Headline numbers");
  const width = Math.max(...m.headline.map((r) => r.label.length));
  const valueWidth = Math.max(...m.headline.map((r) => String(r.value).length));
  for (const r of m.headline) {
    const line = `${r.label.padEnd(width)}  ${String(r.value).padStart(valueWidth)}`;
    out.push(r.change ? `${line}  ${r.change}` : line);
  }
  if (m.changeNotes.length > 0) out.push("", ...m.changeNotes);

  for (const s of m.sections) {
    heading(s.heading);
    out.push(s.lead);
    if (s.notes.length > 0) out.push(...s.notes);
    if (s.empty) out.push(s.empty);
    for (const item of s.items) {
      const badges = item.badges.map((b) => `[${b.text}]`).join(" ");
      out.push("", `* ${item.title}${badges ? ` ${badges}` : ""}`);
      for (const d of item.details) out.push(`  ${d}`);
    }
    if (s.more > 0) {
      out.push("", m.reportUrl ? `${moreLine(s.more)}: ${m.reportUrl}` : moreLine(s.more));
    }
  }

  heading("Estate");
  out.push(m.estate);
  out.push(
    "",
    "--",
    "Sent by upkeep.sh. Change or stop this report under Reports in the dashboard.",
  );
  return `${out.join("\n")}\n`;
}
