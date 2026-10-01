package purl

import (
	"regexp"
	"strings"
)

// typeRule is how one purl type maps to software_versions.
type typeRule struct {
	// Ecosystem is software_versions.ecosystem. It is the purl type
	// itself for every known type
	// (docs/decisions/container-image-vulnerabilities.md: "ecosystem from the
	// package URL type"), kept explicit so a rename is one line.
	Ecosystem string
	// DistroScoped: versions only mean something within one distro
	// release (advisories are per release), so distro/release come from
	// the image's os-release. Otherwise both are ''.
	DistroScoped bool
	// Epoch: an "epoch" qualifier is folded into the version as "N:",
	// the form dpkg and rpm print and hosts store.
	Epoch bool
	// Upstream: the "upstream" qualifier names the source package
	// (deb source, apk origin, rpm source rpm).
	Upstream func(q string) (name, version string, ok bool)
	// Name builds the stored name from namespace and name; nil = the
	// name alone.
	Name func(namespace, name string) string
}

// knownTypes is the explicit table of purl types we recognize. A type not
// listed is still stored (inventory first; see Map), under its own type
// as the ecosystem and "namespace/name" as the name.
//
// Stored names use the form OSV uses for the ecosystem, so OSV matching
// can join on name without a translation step:
//
//	npm     "@scope/name" (scope from the namespace, '@' ensured)
//	pypi    PEP 503 normalised: lowercase, runs of "-_." become "-"
//	golang  the module path: namespace + "/" + name
//	maven   "groupId:artifactId"
//	others  the name (composer, swift, ... that have namespaces:
//	        "namespace/name")
var knownTypes = map[string]typeRule{
	"deb":  {Ecosystem: "deb", DistroScoped: true, Epoch: true, Upstream: upstreamAt},
	"apk":  {Ecosystem: "apk", DistroScoped: true, Upstream: upstreamAt},
	"rpm":  {Ecosystem: "rpm", DistroScoped: true, Epoch: true, Upstream: upstreamSRPM},
	"alpm": {Ecosystem: "alpm", DistroScoped: true, Upstream: upstreamAt},

	"npm":       {Ecosystem: "npm", Name: npmName},
	"pypi":      {Ecosystem: "pypi", Name: pypiName},
	"golang":    {Ecosystem: "golang", Name: slashName},
	"maven":     {Ecosystem: "maven", Name: mavenName},
	"cargo":     {Ecosystem: "cargo"},
	"gem":       {Ecosystem: "gem"},
	"nuget":     {Ecosystem: "nuget"},
	"composer":  {Ecosystem: "composer", Name: slashName},
	"hex":       {Ecosystem: "hex"},
	"pub":       {Ecosystem: "pub"},
	"swift":     {Ecosystem: "swift", Name: slashName},
	"cocoapods": {Ecosystem: "cocoapods"},
	"conan":     {Ecosystem: "conan"},
	"cran":      {Ecosystem: "cran"},
	"hackage":   {Ecosystem: "hackage"},
	"conda":     {Ecosystem: "conda"},
	"github":    {Ecosystem: "github", Name: slashName}, // GitHub Actions
	"generic":   {Ecosystem: "generic", Name: slashName},
}

// DistroScoped reports whether an ecosystem is interned per distro
// release. Unknown ecosystems are not.
func DistroScoped(ecosystem string) bool {
	for _, r := range knownTypes {
		if r.Ecosystem == ecosystem {
			return r.DistroScoped
		}
	}
	return false
}

func slashName(ns, name string) string {
	if ns == "" {
		return name
	}
	return ns + "/" + name
}

func npmName(ns, name string) string {
	if ns == "" {
		return name
	}
	if !strings.HasPrefix(ns, "@") {
		ns = "@" + ns
	}
	return ns + "/" + name
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

func pypiName(_, name string) string {
	return pypiSep.ReplaceAllString(strings.ToLower(name), "-")
}

func mavenName(ns, name string) string {
	if ns == "" {
		return name
	}
	return strings.ReplaceAll(ns, "/", ".") + ":" + name
}

// upstreamAt parses "name" or "name@version" (deb source, apk origin).
func upstreamAt(q string) (string, string, bool) {
	name, version, _ := strings.Cut(q, "@")
	name = strings.TrimSpace(name)
	return name, strings.TrimSpace(version), name != ""
}

// upstreamSRPM parses an rpm source rpm file name,
// "openssl-3.0.7-27.el9.src.rpm", into ("openssl", "3.0.7-27.el9"). The
// name may contain '-', version and release may not. Anything else is
// treated as a bare source name.
func upstreamSRPM(q string) (string, string, bool) {
	base, ok := strings.CutSuffix(q, ".src.rpm")
	if !ok {
		base, ok = strings.CutSuffix(q, ".nosrc.rpm")
	}
	if !ok {
		return upstreamAt(q)
	}
	rel := strings.LastIndexByte(base, '-')
	if rel <= 0 {
		return "", "", false
	}
	ver := strings.LastIndexByte(base[:rel], '-')
	if ver <= 0 {
		return "", "", false
	}
	return base[:ver], base[ver+1:], true
}
