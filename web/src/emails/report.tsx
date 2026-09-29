// The scheduled report email (HTML part). Content and caps come from
// report-content.ts, shared with the plain-text part; this file only lays
// it out. Table-based layout from React Email's components, inline styles,
// no images or web fonts, so Gmail and Outlook render it as written.
//
// Preview: `bun run email` (React Email's dev server) renders PreviewProps,
// the shared fixture.

import {
  Body,
  Column,
  Container,
  Head,
  Heading,
  Hr,
  Html,
  Link,
  Preview,
  Row,
  Section,
  Text,
} from "react-email";
import { Fragment, type CSSProperties } from "react";
import type { ReportSnapshot } from "@/lib/report-snapshot";
import example from "@/lib/report-snapshot.example.json";
import {
  moreLine,
  reportEmailModel,
  type Badge,
  type HeadlineRow,
  type Section as ModelSection,
  type Tone,
} from "./report-content";

export type ReportEmailProps = {
  snapshot: ReportSnapshot;
  /** Absolute link to the report page; null when SW_DASHBOARD_URL is unset. */
  reportUrl: string | null;
};

const font = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";

const s = {
  body: { backgroundColor: "#f4f4f5", fontFamily: font, margin: 0, padding: "24px 0" },
  container: {
    backgroundColor: "#ffffff",
    border: "1px solid #e4e4e7",
    borderRadius: "8px",
    maxWidth: "640px",
    padding: "24px",
  },
  h1: { color: "#18181b", fontSize: "22px", lineHeight: "28px", margin: "0 0 4px" },
  h2: { color: "#18181b", fontSize: "17px", lineHeight: "24px", margin: "24px 0 4px" },
  muted: { color: "#71717a", fontSize: "13px", lineHeight: "20px", margin: "0 0 8px" },
  text: { color: "#27272a", fontSize: "14px", lineHeight: "20px", margin: "0 0 8px" },
  link: { color: "#2563eb", textDecoration: "underline" },
  metricLabel: { color: "#3f3f46", fontSize: "14px", padding: "4px 0" },
  metricValue: {
    color: "#18181b",
    fontSize: "14px",
    fontWeight: 600,
    padding: "4px 12px",
    textAlign: "right",
    width: "64px",
  },
  metricChange: { color: "#71717a", fontSize: "13px", padding: "4px 0", width: "120px" },
  item: {
    borderTop: "1px solid #f4f4f5",
    color: "#52525b",
    fontSize: "13px",
    lineHeight: "18px",
    margin: 0,
    padding: "8px 0",
  },
  itemTitle: { color: "#18181b", fontSize: "14px" },
  hr: { borderColor: "#e4e4e7", margin: "24px 0 12px" },
} satisfies Record<string, CSSProperties>;

const badgeTone: Record<Tone, CSSProperties> = {
  danger: { backgroundColor: "#fee2e2", color: "#991b1b" },
  warning: { backgroundColor: "#fef3c7", color: "#92400e" },
  neutral: { backgroundColor: "#f4f4f5", color: "#3f3f46" },
};

// Kept to a few properties: an item has up to four badges, each repeating
// its style, and the whole email has a size budget.
function BadgeLabel({ badge }: { badge: Badge }) {
  return (
    <>
      {" "}
      <span style={{ ...badgeTone[badge.tone], fontSize: "11px", padding: "1px 4px" }}>
        {badge.text}
      </span>
    </>
  );
}

function Headline({ rows }: { rows: HeadlineRow[] }) {
  return (
    <Section>
      {rows.map((r) => (
        <Row key={r.key}>
          <Column style={s.metricLabel}>{r.label}</Column>
          <Column style={s.metricValue}>{r.value}</Column>
          <Column style={s.metricChange}>{r.change ?? ""}</Column>
        </Row>
      ))}
    </Section>
  );
}

function More({ n, reportUrl }: { n: number; reportUrl: string | null }) {
  if (n <= 0) return null;
  return (
    <Text style={s.text}>
      {reportUrl ? (
        <Link href={reportUrl} style={s.link}>
          {moreLine(n)}
        </Link>
      ) : (
        moreLine(n)
      )}
    </Text>
  );
}

function ReportSection({
  section,
  reportUrl,
}: {
  section: ModelSection;
  reportUrl: string | null;
}) {
  return (
    <Section>
      <Heading as="h2" style={s.h2}>
        {section.heading}
      </Heading>
      <Text style={s.muted}>{section.lead}</Text>
      {section.notes.map((n) => (
        <Text key={n} style={s.text}>
          {n}
        </Text>
      ))}
      {section.empty ? <Text style={s.text}>{section.empty}</Text> : null}
      {/* One paragraph per item, lines split by <br>: every extra element
          repeats its inline style, and a long report must stay under 102 KB. */}
      {section.items.map((item, i) => (
        <Text key={i} style={s.item}>
          <b style={s.itemTitle}>{item.title}</b>
          {item.badges.map((b) => (
            <BadgeLabel key={b.text} badge={b} />
          ))}
          {item.details.map((d, j) => (
            <Fragment key={j}>
              <br />
              {d}
            </Fragment>
          ))}
        </Text>
      ))}
      <More n={section.more} reportUrl={reportUrl} />
    </Section>
  );
}

export default function ReportEmail({ snapshot, reportUrl }: ReportEmailProps) {
  const m = reportEmailModel(snapshot, reportUrl);
  return (
    <Html lang="en">
      <Head />
      <Preview>{m.preheader}</Preview>
      <Body style={s.body}>
        <Container style={s.container}>
          <Heading as="h1" style={s.h1}>
            {m.title}
          </Heading>
          <Text style={s.muted}>{m.period}</Text>
          {m.reportUrl ? (
            <Text style={s.text}>
              <Link href={m.reportUrl} style={s.link}>
                Open the full report
              </Link>
            </Text>
          ) : null}

          <Heading as="h2" style={s.h2}>
            Headline numbers
          </Heading>
          <Headline rows={m.headline} />
          {m.changeNotes.map((n) => (
            <Text key={n} style={s.muted}>
              {n}
            </Text>
          ))}

          {m.sections.map((section) => (
            <ReportSection key={section.id} section={section} reportUrl={m.reportUrl} />
          ))}

          <Heading as="h2" style={s.h2}>
            Estate
          </Heading>
          <Text style={s.text}>{m.estate}</Text>

          <Hr style={s.hr} />
          <Text style={s.muted}>
            Sent by upkeep.sh. Change or stop this report under Reports in the dashboard.
          </Text>
        </Container>
      </Body>
    </Html>
  );
}

ReportEmail.PreviewProps = {
  snapshot: example as ReportSnapshot,
  reportUrl: "http://localhost:3000/dashboard/reports/00000000-0000-0000-0000-000000000000",
} satisfies ReportEmailProps;
