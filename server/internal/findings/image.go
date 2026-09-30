package findings

import (
	"github.com/pippinmole/upkeep.sh/server/internal/matcher"
	"github.com/pippinmole/upkeep.sh/server/internal/severity"
)

// Container image findings and scores
// (docs/decisions/container-image-vulnerabilities.md, follow-up decisions).
//
// A host gets vulnerable_image findings for an image only while at least
// one current container on it uses the image (any state: an exited
// container can be started again); the store decides that scope and
// which package list applies (the one effective for the host's owner).
// Every image, used or not, gets a Score.
//
// Kernel binaries inside an image are skipped, for findings and scores:
// a container runs the host's kernel, never the image's, so the
// running-kernel policy (matcher.RaisesFinding) would always say "not
// running". The host's own kernel is covered by vulnerable_package.

// Image is the image a vulnerable_image finding is about, with what the UI
// shows to link back to it.
type Image struct {
	ID, OS, Arch, Variant string   // the container_images key
	Refs                  []string // repo tags on the host (repo digests when untagged)
	Containers            []string // names of the current containers using it
}

// ImageDedupKey is findings.dedup_key for an image package vulnerability.
// The image id alone identifies the image on a host (host_images keys
// ranges by it).
func ImageDedupKey(imageID, source, vulnKey string) string {
	return "img:" + imageID + ":" + source + ":" + vulnKey
}

// BuildImage groups the matches of an image's package list into desired
// vulnerable_image findings for one host, one per (source package,
// vuln_key), exactly as Build does for host packages. cves maps vuln_key
// to its enrichment. The result is sorted by DedupKey.
func BuildImage(img Image, rows []HostMatch, cves map[string]CVE) []Desired {
	return group(rows, cves, func(r HostMatch) (string, bool, bool) {
		return ImageDedupKey(img.ID, r.Source, r.Match.VulnKey), r.KernelRelease == "", false
	}, func(d *Desired) {
		d.Kind = KindVulnerableImage
		im := img
		d.Image = &im
	})
}

// Score summarises an image's vulnerabilities (image_sbom_scores): the
// worst severity bucket plus counts per bucket, max CVSS and KEV, from the
// same grouping and severity.Assess as findings.
type Score struct {
	Vulns    int
	ByBucket map[severity.Bucket]int
	Worst    severity.Bucket // 0 = no vulnerabilities
	TopKey   severity.Key
	KEV      int
	Fixable  int      // fix available in the standard channel
	MaxCVSS  *float64 // nil = no vulnerability has a CVSS score
}

// ScoreOf scores an image list's matches (see BuildImage).
func ScoreOf(rows []HostMatch, cves map[string]CVE) Score {
	return ScoreGroups(BuildImage(Image{}, rows, cves))
}

// ScoreGroups scores the groups BuildImage returned for a list: the
// store keeps both, the groups row by row and their Score as totals.
func ScoreGroups(ds []Desired) Score {
	sc := Score{Vulns: len(ds), ByBucket: map[severity.Bucket]int{}}
	for _, d := range ds {
		sc.ByBucket[d.Severity.Bucket]++
		sc.Worst = max(sc.Worst, d.Severity.Bucket)
		sc.TopKey = max(sc.TopKey, d.Severity.Key)
		if d.CVE.KEV {
			sc.KEV++
		}
		if d.FixChannel == matcher.ChannelStandard {
			sc.Fixable++
		}
		if c := d.CVE.CVSS; c != nil && (sc.MaxCVSS == nil || *c > *sc.MaxCVSS) {
			v := *c
			sc.MaxCVSS = &v
		}
	}
	return sc
}
