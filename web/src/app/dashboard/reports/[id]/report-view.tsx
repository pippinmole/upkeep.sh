import Link from "next/link";
import type { ReactNode } from "react";

import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { vulnHref } from "@/components/vuln/links";
import { AGENT_STATUS_LABEL, agentStatusTone, StatusBadge } from "@/components/status";
import { Badge } from "@/components/ui/badge";
import { type ReportEmailModel, type SectionId } from "@/emails/report-content";
import { imageHref, platformLabel, shortImageId } from "@/lib/image-key";
import { formatRunAt } from "@/lib/report-schedules";
import type {
  ReportHostAction,
  ReportHostRef,
  ReportImageAction,
  ReportSnapshot,
  ReportTier,
} from "@/lib/report-snapshot";
import { formatEpss } from "@/lib/severity";
import { cn } from "@/lib/utils";

// The full stored report on the dashboard: the same headline, change notes
// and section wording as the email (report-content.ts), drawn with the
// dashboard's components, every list uncapped and linked to host, image
// and vulnerability pages.

const TIER_LABEL: Record<ReportTier, string> = {
  patch_now: "Patch now",
  patch_this_week: "Patch this week",
  when_convenient: "When convenient",
};

const linkClass = "underline-offset-4 hover:underline";

function hostPath(id: string): string {
  return `/dashboard/hosts/${id}`;
}

function HostLinks({ hosts }: { hosts: ReportHostRef[] }) {
  if (hosts.length === 0) return <span className="text-muted-foreground">none</span>;
  return (
    <>
      {hosts.map((h, i) => (
        <span key={h.id}>
          {i > 0 && ", "}
          <Link href={hostPath(h.id)} className={linkClass}>
            {h.name}
          </Link>
        </span>
      ))}
    </>
  );
}

function CveLinks({ cves }: { cves: string[] }) {
  return (
    <>
      {cves.map((id, i) => (
        <span key={id}>
          {i > 0 && ", "}
          <Link href={vulnHref(id)} className={cn(linkClass, "font-mono text-xs")}>
            {id}
          </Link>
        </span>
      ))}
    </>
  );
}

function RiskBadges(a: {
  kev: boolean;
  worst_severity: ReportHostAction["worst_severity"];
  max_epss: number | null;
}) {
  const epss = formatEpss(a.max_epss);
  return (
    <>
      {a.kev && <KevBadge />}
      <SeverityBadge severity={a.worst_severity} />
      {epss && (
        <Badge variant="outline" className="font-normal whitespace-nowrap">
          EPSS {epss}
        </Badge>
      )}
    </>
  );
}

function Detail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="text-sm">
      <span className="text-muted-foreground">{label}: </span>
      {children}
    </div>
  );
}

function Item({
  title,
  badges,
  children,
}: {
  title: ReactNode;
  badges?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <li className="border-border/60 flex flex-col gap-1.5 border-t py-3 first:border-t-0">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium break-all">{title}</span>
        {badges}
      </div>
      {children}
    </li>
  );
}

function HostActionItem({ a, tz }: { a: ReportHostAction; tz: string }) {
  const binaries =
    a.binary_packages.length > 0 &&
    !(a.binary_packages.length === 1 && a.binary_packages[0] === a.package);
  return (
    <Item
      title={
        <>
          {a.package} <span className="text-muted-foreground">→</span>{" "}
          <span className="font-mono text-sm">{a.fixed_version}</span>
        </>
      }
      badges={
        <>
          <RiskBadges {...a} />
          {a.requires_pro && (
            <Badge
              variant="outline"
              className="border-accent-pro/40 bg-accent-pro/10 text-accent-pro-fg whitespace-nowrap"
            >
              Ubuntu Pro
            </Badge>
          )}
        </>
      }
    >
      <Detail label={a.host_count === 1 ? "1 host" : `${a.host_count} hosts`}>
        <HostLinks hosts={a.hosts} />
      </Detail>
      <Detail
        label={`Closes ${a.cve_count} ${a.cve_count === 1 ? "vulnerability" : "vulnerabilities"}`}
      >
        <CveLinks cves={a.cves} />
      </Detail>
      {binaries && <Detail label="Installed as">{a.binary_packages.join(", ")}</Detail>}
      <Detail label="Open since">{formatRunAt(a.oldest_open_at, tz)}</Detail>
    </Item>
  );
}

function imageTitle(i: { image_id: string; image_refs: string[] }): string {
  return i.image_refs.length > 0 ? i.image_refs.join(", ") : shortImageId(i.image_id);
}

function ImageLink(i: {
  image_id: string;
  image_refs: string[];
  os: string;
  arch: string;
  variant: string;
}) {
  return (
    <>
      <Link href={imageHref(i.image_id, { platform: i })} className={linkClass}>
        {imageTitle(i)}
      </Link>{" "}
      <span className="text-muted-foreground text-sm font-normal">({platformLabel(i)})</span>
    </>
  );
}

function ImageActionItem({ a, tz }: { a: ReportImageAction; tz: string }) {
  return (
    <Item
      title={<ImageLink {...a} />}
      badges={
        <>
          <Badge variant="outline" className="font-normal whitespace-nowrap">
            {TIER_LABEL[a.tier]}
          </Badge>
          <RiskBadges {...a} />
        </>
      }
    >
      <div className="text-sm">
        {a.fixable_findings} of {a.open_findings} {a.open_findings === 1 ? "finding" : "findings"}{" "}
        fixed by re-pulling or rebuilding
      </div>
      <Detail
        label={a.containers.length === 1 ? "1 container" : `${a.containers.length} containers`}
      >
        {a.containers.length > 0 ? a.containers.join(", ") : "none"}
      </Detail>
      <Detail label={a.hosts.length === 1 ? "On 1 host" : `On ${a.hosts.length} hosts`}>
        <HostLinks hosts={a.hosts} />
      </Detail>
      <Detail label="Open since">{formatRunAt(a.oldest_open_at, tz)}</Detail>
    </Item>
  );
}

const IMAGE_STATUS: Record<string, string> = {
  pending: "Package list received, not scored yet",
  none: "No package list",
  unavailable: "Package list unavailable",
  error: "Package list failed",
};

function SectionItems({ id, s }: { id: SectionId; s: ReportSnapshot }) {
  const tz = s.schedule.timezone;
  switch (id) {
    case "patch_now":
    case "patch_this_week":
    case "when_convenient": {
      const actions = s.host_actions.filter((a) => a.tier === id);
      if (actions.length === 0) return null;
      return (
        <ul>
          {actions.map((a) => (
            <HostActionItem
              key={`${a.package}|${a.fixed_version}|${a.fix_channel}|${a.hosts.map((h) => h.id).join(",")}`}
              a={a}
              tz={tz}
            />
          ))}
        </ul>
      );
    }
    case "images":
      if (s.image_actions.length === 0) return null;
      return (
        <ul>
          {s.image_actions.map((a) => (
            <ImageActionItem key={`${a.image_id}|${a.os}|${a.arch}|${a.variant}`} a={a} tz={tz} />
          ))}
        </ul>
      );
    case "reboots":
      if (s.reboots_required.length === 0) return null;
      return (
        <ul>
          {s.reboots_required.map((r) => (
            <Item
              key={r.host_id}
              title={
                <Link href={hostPath(r.host_id)} className={linkClass}>
                  {r.host_name}
                </Link>
              }
            >
              {r.packages.length > 0 && <Detail label="For">{r.packages.join(", ")}</Detail>}
              {r.since && <Detail label="Since">{formatRunAt(r.since, tz)}</Detail>}
            </Item>
          ))}
        </ul>
      );
    case "no_fix":
      return null;
    case "coverage": {
      const c = s.coverage;
      if (
        c.stale_agents.length + c.hosts_without_docker.length + c.images_not_scored.length ===
        0
      ) {
        return null;
      }
      return (
        <ul>
          {c.stale_agents.map((a) => (
            <Item
              key={a.agent_id}
              title={`Agent ${a.name} not reporting`}
              badges={
                <StatusBadge tone={agentStatusTone("stale")} label={AGENT_STATUS_LABEL.stale} />
              }
            >
              <div className="text-sm">
                {a.last_seen_at ? `Last seen ${formatRunAt(a.last_seen_at, tz)}` : "Never seen"}
              </div>
              {a.hosts.length > 0 ? (
                <Detail label="Hosts">
                  <HostLinks hosts={a.hosts} />
                </Detail>
              ) : (
                <div className="text-muted-foreground text-sm">No hosts enrolled</div>
              )}
            </Item>
          ))}
          {c.hosts_without_docker.map((h) => (
            <Item
              key={h.id}
              title={
                <>
                  <Link href={hostPath(h.id)} className={linkClass}>
                    {h.name}
                  </Link>
                  : no Docker collection
                </>
              }
            >
              <div className="text-muted-foreground text-sm">
                Containers and images on this host aren&apos;t checked
              </div>
            </Item>
          ))}
          {c.images_not_scored.map((i) => (
            <Item
              key={`${i.image_id}|${i.os}|${i.arch}|${i.variant}`}
              title={
                <>
                  <ImageLink {...i} /> not scored
                </>
              }
            >
              <div className="text-muted-foreground text-sm">
                {IMAGE_STATUS[i.status] ?? i.status}
              </div>
            </Item>
          ))}
        </ul>
      );
    }
  }
}

export function HeadlineGrid({ model }: { model: ReportEmailModel }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      {model.headline.map((h) => (
        <div key={h.key} className="border-border bg-card rounded-lg border p-3">
          <div className="text-muted-foreground text-xs">{h.label}</div>
          <div className="mt-1 text-2xl font-semibold tabular-nums">{h.value}</div>
          {h.change && (
            <div className="text-muted-foreground mt-0.5 text-xs tabular-nums">{h.change}</div>
          )}
        </div>
      ))}
    </div>
  );
}

export function ReportSections({ model, s }: { model: ReportEmailModel; s: ReportSnapshot }) {
  return (
    <div className="flex flex-col gap-4">
      {model.sections.map((sec) => (
        <section
          key={sec.id}
          aria-labelledby={`section-${sec.id}`}
          className="border-border bg-card rounded-lg border p-4"
        >
          <h2 id={`section-${sec.id}`} className="text-lg font-semibold">
            {sec.heading}
          </h2>
          <p className="text-muted-foreground text-sm">{sec.lead}</p>
          {sec.notes.map((n) => (
            <p key={n} className="mt-2 text-sm">
              {n}
            </p>
          ))}
          {sec.empty ? (
            <p className="text-muted-foreground mt-2 text-sm">{sec.empty}</p>
          ) : (
            <div className="mt-2">
              <SectionItems id={sec.id} s={s} />
            </div>
          )}
        </section>
      ))}
    </div>
  );
}
