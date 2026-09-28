// Renders a report snapshot into the three parts the worker sends:
// subject, HTML and plain text (POST /api/internal/render/report).

import { createElement } from "react";
import { render } from "react-email";
import type { ReportSnapshot } from "@/lib/report-snapshot";
import { reportEmailSubject } from "@/lib/report-summary";
import ReportEmail from "./report";
import { reportEmailModel } from "./report-content";
import { reportEmailText } from "./report-text";

export type RenderedEmail = { subject: string; html: string; text: string };

export async function renderReportEmail(
  snapshot: ReportSnapshot,
  reportUrl: string | null,
): Promise<RenderedEmail> {
  const html = await render(createElement(ReportEmail, { snapshot, reportUrl }));
  return {
    subject: reportEmailSubject(snapshot),
    html,
    text: reportEmailText(reportEmailModel(snapshot, reportUrl)),
  };
}
