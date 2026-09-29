import Link from "next/link";

import { ContainerStateBadge, HostLink, shortId } from "@/components/docker-fleet/badges";
import { repoHref } from "@/components/docker-fleet/links";
import { RegistryLogo } from "@/components/brand";
import { scoreTitle } from "@/components/image/score-cell";
import { PageHeader, SectionHeading } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { imageHref, platformLabel, type ImageKey } from "@/lib/image-key";
import { imageScoreState } from "@/lib/image-score";
import type { ImageListState, ImageOverview } from "@/lib/queries-image";
import { SEVERITIES } from "@/lib/severity";
import { formatDate, formatDateTime } from "@/lib/time";
import { cn } from "@/lib/utils";

// Image detail header: names, platform, package list provenance, score,
// and the user's hosts / containers that have the image.

const SOURCE_LABEL: Record<string, string> = {
  attestation: "registry SBOM attestation",
  "server-syft": "server-side Syft scan",
  "agent-syft": "the agent's Syft scan",
};

export function imageTitle(o: Pick<ImageOverview, "tags" | "key">): string {
  return o.tags[0] ?? shortId(o.key.imageId);
}

// "postgres:17" -> "postgres"; "host:5000/app:1" keeps the port.
const repoOf = (tag: string) => tag.replace(/:[^:/]+$/, "");

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0">{children}</dd>
    </>
  );
}

function ListSource({ list }: { list: ImageListState | null }) {
  if (!list || list.status !== "ok")
    return <span className="text-muted-foreground">No package list</span>;
  const tool = [list.toolName, list.toolVersion].filter(Boolean).join(" ");
  return (
    <span>
      From {SOURCE_LABEL[list.source ?? ""] ?? list.source}
      {tool && `, ${tool}`}
      {list.generatedAt && (
        <span className="text-muted-foreground" title={formatDateTime(list.generatedAt)}>
          {" "}
          · generated {formatDate(list.generatedAt)}
        </span>
      )}
    </span>
  );
}

function ScoreSummary({ overview }: { overview: ImageOverview }) {
  const s = overview.score;
  const st = imageScoreState(s, { inspected: true, hasRepoDigest: overview.digests.length > 0 });
  if (!s || st.kind !== "vulnerable") {
    if (st.kind === "no_known") {
      return (
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="success" className="font-normal">
            No known vulnerabilities
          </Badge>
          {st.partial && (
            <span className="text-muted-foreground text-xs">
              {s?.notAssessed} of {s?.packages} packages not assessed
            </span>
          )}
        </div>
      );
    }
    return <span className="text-muted-foreground">No score</span>;
  }
  return (
    <div className="flex flex-col gap-1" title={scoreTitle(s)}>
      <div className="flex flex-wrap items-center gap-1.5">
        {SEVERITIES.filter((sev) => s.counts[sev] > 0).map((sev) => (
          <SeverityBadge key={sev} severity={sev} count={s.counts[sev]} />
        ))}
        {s.kev > 0 && <KevBadge count={s.kev} />}
      </div>
      <span className="text-muted-foreground text-xs">
        {s.vulns} {s.vulns === 1 ? "vulnerability" : "vulnerabilities"}, worst{" "}
        {s.worst ?? "unknown"}
        {s.maxCvss !== null && ` · max CVSS ${s.maxCvss.toFixed(1)}`}
        {` · ${s.fixable} with a fix`}
        {(s.notAssessed ?? 0) > 0 && ` · ${s.notAssessed} of ${s.packages} packages not assessed`}
      </span>
    </div>
  );
}

export function ImageHeader({
  overview,
  platforms,
  uninspected,
}: {
  overview: ImageOverview;
  platforms: ImageKey[]; // every inspected platform of this id on the user's hosts
  uninspected: boolean;
}) {
  const o = overview;
  const repo = o.tags[0] ? repoOf(o.tags[0]) : null;
  const containers = o.hosts.flatMap((h) => h.containers);
  const list = o.list;
  const distro =
    list?.status === "ok" && (list.distroName || list.distro)
      ? `${list.distroName ?? list.distro}${list.release && !(list.distroName ?? "").includes(list.release) ? ` (${list.release})` : ""}`
      : null;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        breadcrumbs={[
          { label: "Images", href: "/dashboard/images" },
          ...(repo ? [{ label: repo, href: repoHref(repo) }] : []),
          { label: o.tags[0] && repo ? o.tags[0].slice(repo.length + 1) : shortId(o.key.imageId) },
        ]}
        title={imageTitle(o)}
        mono
        icon={<RegistryLogo repo={repo} size={24} colored />}
        meta={
          <span>
            {platformLabel(o.key)} · on {o.hosts.length} {o.hosts.length === 1 ? "host" : "hosts"},{" "}
            {containers.length === 0
              ? "no containers (score only, no findings)"
              : `${containers.length} ${containers.length === 1 ? "container" : "containers"}`}
          </span>
        }
      />

      <dl className="bg-card grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 rounded-lg border p-4 text-sm">
        <Fact label="Score">
          <ScoreSummary overview={o} />
        </Fact>
        <Fact label="Package list">
          <ListSource list={list} />
          {list?.status === "ok" && list.packageCount !== null && (
            <span className="text-muted-foreground"> · {list.packageCount} packages</span>
          )}
        </Fact>
        {distro && <Fact label="Distribution">{distro}</Fact>}
        {o.tags.length > 0 && (
          <Fact label="Tags">
            <div className="flex flex-wrap gap-1">
              {o.tags.map((t) => (
                <Badge key={t} variant="outline" className="font-mono text-xs font-normal">
                  {t}
                </Badge>
              ))}
            </div>
          </Fact>
        )}
        <Fact label="Digests">
          {o.digests.length === 0 ? (
            <span className="text-muted-foreground">None (built locally or loaded)</span>
          ) : (
            <div className="flex flex-col gap-0.5 font-mono text-xs break-all">
              {o.digests.map((d) => (
                <span key={d}>{d}</span>
              ))}
            </div>
          )}
        </Fact>
        <Fact label="Image ID">
          <span className="font-mono text-xs break-all">{o.key.imageId}</span>
        </Fact>
        <Fact label="Platform">
          <div className="flex flex-wrap items-center gap-1">
            {platforms.map((p) => {
              const active =
                p.os === o.key.os && p.arch === o.key.arch && p.variant === o.key.variant;
              return (
                <Link
                  key={platformLabel(p)}
                  href={imageHref(p.imageId, { platform: p })}
                  aria-current={active ? "page" : undefined}
                >
                  <Badge
                    variant={active ? "secondary" : "outline"}
                    className={cn(
                      "font-mono text-xs font-normal",
                      !active && "text-muted-foreground",
                    )}
                  >
                    {platformLabel(p)}
                  </Badge>
                </Link>
              );
            })}
            {uninspected && (
              <span className="text-muted-foreground text-xs">
                (some hosts haven&apos;t inspected it yet)
              </span>
            )}
          </div>
        </Fact>
        {o.created && <Fact label="Created">{formatDateTime(o.created)}</Fact>}
      </dl>

      <section className="flex flex-col gap-2">
        <SectionHeading>Hosts and containers</SectionHeading>
        <ul className="bg-card flex flex-col divide-y rounded-lg border">
          {o.hosts.map((h) => (
            <li key={h.hostId} className="flex flex-col gap-1.5 px-4 py-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <HostLink hostId={h.hostId} hostname={h.hostname} label={h.label} tab="images" />
                {h.openFindings > 0 && (
                  <span className="text-muted-foreground text-xs">
                    {h.openFindings} open {h.openFindings === 1 ? "finding" : "findings"}
                  </span>
                )}
              </div>
              {h.containers.length === 0 ? (
                <span className="text-muted-foreground text-xs">
                  No container uses it: scored, but no findings or alerts on this host.
                </span>
              ) : (
                <ul className="flex flex-col gap-1">
                  {h.containers.map((c) => (
                    <li key={c.id} className="flex flex-wrap items-center gap-2">
                      <Link
                        href={`/dashboard/hosts/${h.hostId}/containers`}
                        className="font-mono text-xs hover:underline"
                      >
                        {c.name}
                      </Link>
                      <ContainerStateBadge state={c.state} />
                      {(c.composeProject || c.swarmServiceName) && (
                        <span className="text-muted-foreground text-xs">
                          {c.swarmServiceName
                            ? `service ${c.swarmServiceName}`
                            : `compose ${c.composeProject}`}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
