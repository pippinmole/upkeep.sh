package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/pippinmole/upkeep.sh/server/internal/findings"
)

// Image list vulnerabilities (image_sbom_vulns, migration 0019): the
// per-(source package, vuln_key) groups ScoreImageSBOM counted, one row
// each with the severity.Assess result, so the dashboard lists them
// without re-deriving the ranking rules (DOMAIN_MODEL.md §3.8).

var imageSBOMVulnCols = []string{
	"sbom_id", "source_package", "vuln_key", "ecosystem",
	"installed_version", "fixed_version", "fix_channel", "fix_advisory_id", "advisory_ids",
	"distro_severity", "packages", "software_ids", "severity", "severity_rank", "severity_key",
	"is_kev", "epss_score", "cvss_v3_score",
}

// writeImageSBOMVulns replaces the list's rows with groups (from
// findings.BuildImage), inside the scoring transaction.
func writeImageSBOMVulns(ctx context.Context, tx pgx.Tx, sbomID int64, groups []findings.Desired) error {
	if _, err := tx.Exec(ctx, `DELETE FROM image_sbom_vulns WHERE sbom_id = $1`, sbomID); err != nil {
		return err
	}
	if len(groups) == 0 {
		return nil
	}
	rows := make([][]any, len(groups))
	for i, d := range groups {
		rows[i] = []any{
			sbomID, d.Source, d.VulnKey, d.Ecosystem,
			d.InstalledVersion, d.FixedVersion, nilIfEmpty(d.FixChannel), nilIfEmpty(d.FixAdvisoryID),
			orEmpty(d.AdvisoryIDs), d.DistroSeverity, orEmpty(d.Packages), d.SoftwareIDs,
			d.Severity.Bucket.String(), int(d.Severity.Bucket), int64(d.Severity.Key),
			d.CVE.KEV, d.CVE.EPSS, d.CVE.CVSS,
		}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"image_sbom_vulns"}, imageSBOMVulnCols, pgx.CopyFromRows(rows)); err != nil {
		return fmt.Errorf("write image_sbom_vulns: %w", err)
	}
	return nil
}
