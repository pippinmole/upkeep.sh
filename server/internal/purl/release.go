package purl

import (
	"regexp"
	"strings"
)

// OSRelease is the part of an image's /etc/os-release (as found by the SBOM
// generator) that scopes its distro packages. Empty when the image has
// none (scratch, distroless without os-release).
type OSRelease struct {
	ID              string // "debian", "ubuntu", "alpine", "rhel"
	VersionID       string // "12", "22.04", "3.20.3"
	VersionCodename string // "bookworm", "jammy"; often empty elsewhere
	PrettyName      string // display only
}

// ReleaseIndex maps a distro's version to its codename, e.g.
// {"debian","12"} -> "bookworm". Built from distro_releases
// (store.DistroReleaseIndex); nil is an empty index.
type ReleaseIndex map[ReleaseKey]string

type ReleaseKey struct{ Distro, Version string }

// Codename looks version up exactly, then with trailing ".N" components
// stripped ("12.7" -> "12"), so point releases resolve.
func (ix ReleaseIndex) Codename(distro, version string) (string, bool) {
	for v := version; v != ""; {
		if c, ok := ix[ReleaseKey{distro, v}]; ok {
			return c, true
		}
		i := strings.LastIndexByte(v, '.')
		if i < 0 {
			break
		}
		v = v[:i]
	}
	return "", false
}

// codenameDistros key their releases by codename: that is what hosts send
// (os.codename), what advisories are imported under (distro_releases) and
// so what software_versions.release holds for them.
var codenameDistros = map[string]bool{"debian": true, "ubuntu": true}

var majorMinor = regexp.MustCompile(`^\d+\.\d+`)

// ReleaseFor returns software_versions.release for distro packages of an
// OS: the rule each distro's advisories are keyed by.
//
//	debian, ubuntu  VERSION_CODENAME, else the codename of VERSION_ID via
//	                ix; "" when neither is known (never the number: a
//	                "12" row would silently split from "bookworm" rows)
//	alpine          major.minor of VERSION_ID ("3.20.3" -> "3.20"),
//	                the Alpine secdb / OSV "Alpine:v3.20" branch
//	anything else   VERSION_ID as is (rpm distros: refine when their
//	                advisories land)
//
// Host ingest must use the same rule when it gains apk / rpm (today it
// uses os.codename, which is right for deb only).
func ReleaseFor(osr OSRelease, ix ReleaseIndex) string {
	id := strings.ToLower(osr.ID)
	switch {
	case codenameDistros[id]:
		if osr.VersionCodename != "" {
			return strings.ToLower(osr.VersionCodename)
		}
		c, _ := ix.Codename(id, osr.VersionID)
		return c
	case id == "alpine":
		return majorMinor.FindString(osr.VersionID)
	default:
		return osr.VersionID
	}
}

// distroQualifier matches "<id>-<version>" ("debian-12", "ubuntu-22.04",
// "alpine-3.20.3", "opensuse-leap-15.5"): the id is everything before the
// last '-' that is followed by a digit.
var distroQualifier = regexp.MustCompile(`^(.+)-(\d[0-9A-Za-z._~+]*)$`)

// OSFromQualifier derives an OSRelease from a distro package's purl
// "distro" qualifier, for images whose SBOM carries no os-release. Forms
// seen in the wild:
//
//	distro=debian-12      id-version (Syft, Trivy)
//	distro=3.20.3         version only: the id is the purl namespace
//	distro=bookworm       codename only (purl-spec deb examples)
//
// ok is false when the purl has no distro qualifier.
func OSFromQualifier(p PURL) (OSRelease, bool) {
	q := p.Qualifier("distro")
	if q == "" {
		return OSRelease{}, false
	}
	ns := strings.ToLower(p.Namespace)
	if m := distroQualifier.FindStringSubmatch(q); m != nil {
		return OSRelease{ID: strings.ToLower(m[1]), VersionID: m[2]}, true
	}
	if q[0] >= '0' && q[0] <= '9' {
		return OSRelease{ID: ns, VersionID: q}, ns != ""
	}
	return OSRelease{ID: ns, VersionCodename: q}, ns != ""
}
