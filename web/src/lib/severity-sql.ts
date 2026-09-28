// SQL MIRROR of server/internal/severity.Assess (via findings.Assess): the
// display bucket and sort key of one (package, vulnerability) match.
//
// Why a mirror: the Go side stores its result on findings (severity,
// severity_key) and per image list only as totals (image_sbom_scores). An
// image no container uses has a score but no findings, yet its
// Vulnerabilities and Packages tabs need a bucket per row, so the image
// pages assess software_vulnerabilities rows here. Keep it in step with
// severity.go; the image detail page's rows must add up to the Go-computed
// score counts, and for images with findings the key equals
// findings.severity_key (both checked against real data when this was
// written; see DOMAIN_MODEL.md §3.8). The rest of the dashboard only
// displays what Go wrote.
//
// Rules (severity.go package doc): bucket = distro priority's bucket,
// raised by the EPSS band (>= 0.01 medium, >= 0.10 high, >= 0.50
// critical) unless the distro triaged it negligible, and critical when in
// KEV. Key bits, most significant first: bucket 3 | kev 1 | epss band 2 |
// priority bucket 3 | fix available 1 | epss*1e6 20 | cvss*10+1 7.
// Buckets are severity_rank values: negligible 1, low 2, unknown 3,
// medium 4, high 5, critical 6.

export const BUCKET_NAMES_SQL = `(ARRAY['negligible','low','unknown','medium','high','critical'])`;

// severity.ParsePriority: case-insensitive, trailing "*" uncertainty
// markers dropped, "_" / "-" read as spaces; unrecognised = unknown.
function priorityBucketSql(col: string): string {
  return `CASE translate(rtrim(lower(btrim(coalesce(${col}, ''), E' \\t\\n\\r')), '*'), '_-', '  ')
      WHEN 'unimportant' THEN 1 WHEN 'negligible' THEN 1 WHEN 'low' THEN 2
      WHEN 'medium' THEN 4 WHEN 'high' THEN 5 WHEN 'critical' THEN 6 ELSE 3 END`;
}

// A LATERAL join exposing `<alias>.bucket` (int), `<alias>.severity` (text)
// and `<alias>.severity_key` (bigint) for one match row. Arguments are
// column expressions of the enclosing query: the match's distro severity and
// fix channel, and the cves row's is_kev / epss_score / cvss_v3_score (NULL
// when there is none; Go only enriches CVE-* keys, so join cves with
// `vuln_key LIKE 'CVE-%'`).
export function severityLateral(
  alias: string,
  c: { distroSeverity: string; fixChannel: string; kev: string; epss: string; cvss: string },
): string {
  return `CROSS JOIN LATERAL (
    SELECT x.bucket, ${BUCKET_NAMES_SQL}[x.bucket] AS severity,
           ((((((x.bucket::bigint << 1) | x.kev) << 2 | x.band) << 3 | x.pri) << 1 | x.fix) << 20
             | x.epss_i) << 7 | x.cvss_i AS severity_key
    FROM (
      SELECT p.*,
             CASE WHEN p.kev = 1 THEN 6 WHEN p.pri = 1 THEN p.pri
                  ELSE greatest(p.pri, (ARRAY[0, 4, 5, 6])[p.band + 1]) END AS bucket
      FROM (
        SELECT ${priorityBucketSql(c.distroSeverity)} AS pri,
               CASE WHEN coalesce(${c.kev}, false) THEN 1 ELSE 0 END AS kev,
               CASE WHEN coalesce(${c.epss}, 0) >= 0.50 THEN 3
                    WHEN coalesce(${c.epss}, 0) >= 0.10 THEN 2
                    WHEN coalesce(${c.epss}, 0) >= 0.01 THEN 1 ELSE 0 END AS band,
               CASE WHEN ${c.fixChannel} = 'standard' THEN 1 ELSE 0 END AS fix,
               round(least(greatest(coalesce(${c.epss}, 0)::numeric, 0), 1) * 1000000)::bigint AS epss_i,
               CASE WHEN ${c.cvss} IS NULL THEN 0
                    ELSE round(least(greatest(${c.cvss}::numeric, 0), 10) * 10)::bigint + 1 END AS cvss_i
      ) p
    ) x
  ) ${alias}`;
}
